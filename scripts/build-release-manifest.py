#!/usr/bin/env python3
"""Unified Core Release Manifest builder and verifier (stdlib-only Python 3).

Reads authoritative version and protocol metadata directly from `rabbitcontrol-core`:
- Root `Cargo.toml` (`[workspace.package].version`)
- `CORE_ABI_VERSION` (`crates/rc-client-core/src/version.rs`)
- `PROTOCOL_VERSION` (`crates/rc-session/src/proto.rs`)
- `PUNCH_VERSION` (`crates/rc-client-core/src/p2p.rs`)
- `BEACON_VERSION` (`crates/rc-client-core/src/lan_discovery.rs`)

Supports:
- Strict tag vs `Cargo.toml` version verification (`--verify-tag`)
- Merging multi-platform artifact manifests and `SHA256SUMS.txt` files into a
  deterministic, machine-readable `release-manifest.json`
- Offline self-test (`--self-test`) with zero network access
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any

SCHEMA_VERSION = "1.0.0"
DEFAULT_PLATFORMS = ("macos", "ios", "android", "windows", "linux")
SEMVER_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
CONST_INT_TMPL = r"\bpub\s+const\s+{name}\s*:\s*u(?:8|16|32|64)\s*=\s*([0-9_]+)\s*;"


def read_workspace_version(repo_root: pathlib.Path) -> str:
    """Parse `[workspace.package].version` from root `Cargo.toml`."""
    cargo_toml = repo_root / "Cargo.toml"
    text = cargo_toml.read_text(encoding="utf-8")

    # Use stdlib tomllib when available (Python 3.11+).
    try:
        import tomllib  # type: ignore[import-not-found]

        data = tomllib.loads(text)
        version = data.get("workspace", {}).get("package", {}).get("version")
        if not isinstance(version, str) or not version.strip():
            raise ValueError("missing [workspace.package].version in Cargo.toml")
        version = version.strip()
    except ModuleNotFoundError:
        in_section = False
        version = ""
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                in_section = line == "[workspace.package]"
                continue
            if in_section:
                m = re.match(r'^version\s*=\s*"([^"]+)"\s*$', line)
                if m:
                    version = m.group(1).strip()
                    break
        if not version:
            raise ValueError("missing [workspace.package].version in Cargo.toml")

    if not SEMVER_RE.match(version):
        raise ValueError(f"invalid workspace version in Cargo.toml: {version!r}")
    return version


def read_rust_const_int(path: pathlib.Path, const_name: str) -> int:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(CONST_INT_TMPL.format(name=re.escape(const_name)))
    match = pattern.search(text)
    if not match:
        raise ValueError(f"could not locate `pub const {const_name}` in {path}")
    return int(match.group(1).replace("_", ""))


def read_git_commit(repo_root: pathlib.Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            commit = proc.stdout.strip()
            if commit:
                return commit
    except OSError:
        pass
    return "unknown"


def read_spec_version(repo_root: pathlib.Path) -> str | None:
    lock_path = repo_root / "spec-lock.json"
    if not lock_path.is_file():
        return None
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    val = data.get("spec_version")
    return val.strip() if isinstance(val, str) and val.strip() else None


def read_core_metadata(repo_root: pathlib.Path) -> dict[str, Any]:
    core_version = read_workspace_version(repo_root)
    abi_version = read_rust_const_int(
        repo_root / "crates" / "rc-client-core" / "src" / "version.rs",
        "CORE_ABI_VERSION",
    )
    session_proto = read_rust_const_int(
        repo_root / "crates" / "rc-session" / "src" / "proto.rs",
        "PROTOCOL_VERSION",
    )
    punch_proto = read_rust_const_int(
        repo_root / "crates" / "rc-client-core" / "src" / "p2p.rs",
        "PUNCH_VERSION",
    )
    beacon_proto = read_rust_const_int(
        repo_root / "crates" / "rc-client-core" / "src" / "lan_discovery.rs",
        "BEACON_VERSION",
    )
    meta: dict[str, Any] = {
        "coreVersion": core_version,
        "abiVersion": abi_version,
        "protocolVersions": {
            "session": session_proto,
            "punch": punch_proto,
            "beacon": beacon_proto,
        },
    }
    spec_ver = read_spec_version(repo_root)
    if spec_ver is not None:
        meta["specVersion"] = spec_ver
    return meta


def verify_tag_matches_version(tag: str, core_version: str) -> None:
    cleaned = tag.strip()
    if not cleaned.startswith("v"):
        raise ValueError(
            f"release tag must start with 'v' (got {tag!r}, expected 'v{core_version}')"
        )
    tag_version = cleaned[1:]
    if tag_version != core_version:
        raise ValueError(
            f"release tag version mismatch: tag={tag!r} ({tag_version!r}) != Cargo.toml workspace.package.version ({core_version!r})"
        )


def validate_artifact_name(name: str) -> str:
    cleaned = name.strip()
    if (
        not cleaned
        or cleaned.startswith(".")
        or cleaned.startswith("-")
        or "/" in cleaned
        or "\\" in cleaned
        or ".." in cleaned
        or not SAFE_ARTIFACT_NAME_RE.match(cleaned)
    ):
        raise ValueError(f"unsafe artifact filename: {name!r}")
    return cleaned


def validate_sha256(digest: str) -> str:
    cleaned = digest.strip().lower()
    if not SHA256_RE.match(cleaned):
        raise ValueError(f"invalid SHA-256 hex digest: {digest!r}")
    return cleaned


def parse_sha256sums_text(text: str) -> dict[str, str]:
    """Parse standard `SHA256SUMS.txt` lines (`<64-hex>  <filename>` or `<64-hex> *<filename>`)."""
    checksums: dict[str, str] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line)
        if not match:
            raise ValueError(f"malformed SHA256SUMS line {lineno}: {raw_line!r}")
        digest = validate_sha256(match.group(1))
        filename = validate_artifact_name(match.group(2))
        if filename in checksums and checksums[filename] != digest:
            raise ValueError(
                f"conflicting SHA-256 for {filename!r}: {checksums[filename]} vs {digest}"
            )
        checksums[filename] = digest
    return checksums


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(
    repo_root: pathlib.Path,
    *,
    tag: str | None = None,
    git_commit: str | None = None,
    min_client_overrides: dict[str, str] | None = None,
    checksum_files: list[pathlib.Path] | None = None,
    platform_manifest_files: list[pathlib.Path] | None = None,
    artifacts_dir: pathlib.Path | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    meta = read_core_metadata(repo_root)
    core_version = meta["coreVersion"]
    if tag is not None:
        verify_tag_matches_version(tag, core_version)

    commit = (git_commit or "").strip() or read_git_commit(repo_root)

    min_clients: dict[str, str] = {p: core_version for p in DEFAULT_PLATFORMS}
    for plat, ver in (min_client_overrides or {}).items():
        plat_key = plat.strip().lower()
        ver_clean = ver.strip()
        if not plat_key:
            raise ValueError("min-client-version platform key must not be empty")
        if not SEMVER_RE.match(ver_clean):
            raise ValueError(
                f"invalid min-client-version for {plat_key!r}: {ver!r}"
            )
        min_clients[plat_key] = ver_clean

    merged_checksums: dict[str, str] = {}

    def record_checksum(name: str, digest: str) -> None:
        safe_name = validate_artifact_name(name)
        safe_digest = validate_sha256(digest)
        existing = merged_checksums.get(safe_name)
        if existing is not None and existing != safe_digest:
            raise ValueError(
                f"conflicting SHA-256 for artifact {safe_name!r}: {existing} vs {safe_digest}"
            )
        merged_checksums[safe_name] = safe_digest

    for sum_path in checksum_files or []:
        parsed = parse_sha256sums_text(sum_path.read_text(encoding="utf-8"))
        for fname, digest in parsed.items():
            record_checksum(fname, digest)

    platforms: dict[str, dict[str, Any]] = {}

    for frag_path in platform_manifest_files or []:
        frag = json.loads(frag_path.read_text(encoding="utf-8"))
        if not isinstance(frag, dict):
            raise ValueError(f"platform manifest must be a JSON object: {frag_path}")
        if "platforms" in frag and isinstance(frag["platforms"], dict):
            entries = frag["platforms"]
        elif "platform" in frag and isinstance(frag["platform"], str):
            plat_name = frag["platform"].strip().lower()
            entries = {
                plat_name: {
                    k: v for k, v in frag.items() if k != "platform"
                }
            }
        else:
            raise ValueError(
                f"platform manifest must specify 'platform' or 'platforms': {frag_path}"
            )

        for plat_key, plat_val in entries.items():
            key = str(plat_key).strip().lower()
            if not key or not isinstance(plat_val, dict):
                raise ValueError(f"invalid platform entry {plat_key!r} in {frag_path}")
            artifacts_in = plat_val.get("artifacts", [])
            if not isinstance(artifacts_in, list):
                raise ValueError(
                    f"platform {key!r} 'artifacts' must be a list in {frag_path}"
                )
            norm_artifacts: list[dict[str, Any]] = []
            for idx, art in enumerate(artifacts_in):
                if not isinstance(art, dict):
                    raise ValueError(
                        f"platform {key!r} artifacts[{idx}] must be an object"
                    )
                art_name = validate_artifact_name(str(art.get("name", "")))
                art_sha = validate_sha256(str(art.get("sha256", "")))
                record_checksum(art_name, art_sha)
                norm_art: dict[str, Any] = {
                    "name": art_name,
                    "sha256": art_sha,
                }
                if "size" in art:
                    size_val = art["size"]
                    if (
                        isinstance(size_val, bool)
                        or not isinstance(size_val, int)
                        or size_val < 0
                    ):
                        raise ValueError(
                            f"platform {key!r} artifact {art_name!r} has invalid size"
                        )
                    norm_art["size"] = size_val
                for opt_field in ("arch", "format", "url", "minOsVersion"):
                    if opt_field in art and art[opt_field] is not None:
                        norm_art[opt_field] = str(art[opt_field])
                norm_artifacts.append(norm_art)

            norm_artifacts.sort(key=lambda item: item["name"])
            target_plat = platforms.setdefault(key, {"artifacts": []})
            by_name = {a["name"]: a for a in target_plat["artifacts"]}
            for a in norm_artifacts:
                by_name[a["name"]] = a
            target_plat["artifacts"] = [by_name[k] for k in sorted(by_name)]
            for extra_key in ("repo", "version", "commit"):
                if extra_key in plat_val and plat_val[extra_key] is not None:
                    target_plat[extra_key] = str(plat_val[extra_key])

    if artifacts_dir is not None and artifacts_dir.is_dir():
        for entry in sorted(artifacts_dir.iterdir(), key=lambda p: p.name):
            if entry.is_symlink() or not entry.is_file():
                continue
            if entry.name in ("release-manifest.json", "SHA256SUMS.txt"):
                continue
            record_checksum(entry.name, sha256_file(entry))

    # Attach any standalone checksums not yet attached to a named platform under `unclassified`.
    attached_names = {
        art["name"]
        for pdata in platforms.values()
        for art in pdata.get("artifacts", [])
    }
    orphan_names = sorted(set(merged_checksums) - attached_names)
    if orphan_names:
        platforms["checksumsOnly"] = {
            "artifacts": [
                {"name": name, "sha256": merged_checksums[name]}
                for name in orphan_names
            ]
        }

    manifest: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "coreVersion": core_version,
        "tag": tag.strip() if tag else f"v{core_version}",
        "gitCommit": commit,
        "abiVersion": meta["abiVersion"],
        "protocolVersions": meta["protocolVersions"],
        "minClientVersions": dict(sorted(min_clients.items())),
        "platforms": {k: platforms[k] for k in sorted(platforms)},
    }
    if "specVersion" in meta:
        manifest["specVersion"] = meta["specVersion"]
    return manifest, dict(sorted(merged_checksums.items()))


def format_sha256sums(checksums: dict[str, str]) -> str:
    if not checksums:
        return ""
    return "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items()))


def run_self_test(repo_root: pathlib.Path) -> int:
    meta = read_core_metadata(repo_root)
    core_version = meta["coreVersion"]
    assert SEMVER_RE.match(core_version), f"bad coreVersion: {core_version}"
    assert isinstance(meta["abiVersion"], int) and meta["abiVersion"] >= 1
    assert meta["protocolVersions"]["session"] >= 1
    assert meta["protocolVersions"]["punch"] >= 1
    assert meta["protocolVersions"]["beacon"] >= 1

    # 1. Tag verification: exact match passes; mismatch and missing 'v' fail.
    verify_tag_matches_version(f"v{core_version}", core_version)
    for bad_tag in (core_version, "v99.99.99", "release-1.0.0"):
        try:
            verify_tag_matches_version(bad_tag, core_version)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected tag mismatch failure for {bad_tag!r}")

    # 2. Multi-platform manifest + SHA256SUMS merge & conflict / traversal guards.
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = pathlib.Path(tmp_str)
        apple_sha = "a" * 64
        android_sha = "b" * 64
        extra_sha = "c" * 64

        apple_frag = tmp / "apple.json"
        apple_frag.write_text(
            json.dumps(
                {
                    "platform": "ios",
                    "repo": "TokenBoom/rabbitcontrol-apple-media",
                    "artifacts": [
                        {
                            "name": f"RabbitControlCore-{core_version}.xcframework.zip",
                            "sha256": apple_sha,
                            "size": 123456,
                            "arch": "universal",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        android_frag = tmp / "android.json"
        android_frag.write_text(
            json.dumps(
                {
                    "platforms": {
                        "android": {
                            "repo": "TokenBoom/rabbitcontrol-android",
                            "artifacts": [
                                {
                                    "name": f"rabbitcontrol-core-{core_version}-arm64-v8a.aar",
                                    "sha256": android_sha,
                                    "size": 654321,
                                    "arch": "arm64-v8a",
                                }
                            ],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        sums_file = tmp / "SHA256SUMS.txt"
        sums_file.write_text(
            f"{apple_sha}  RabbitControlCore-{core_version}.xcframework.zip\n"
            f"{extra_sha}  rabbitcontrol-core-{core_version}-sources.tar.gz\n",
            encoding="utf-8",
        )

        manifest, checksums = build_manifest(
            repo_root,
            tag=f"v{core_version}",
            git_commit="deadbeef",
            checksum_files=[sums_file],
            platform_manifest_files=[apple_frag, android_frag],
        )
        for required_key in (
            "schemaVersion",
            "coreVersion",
            "gitCommit",
            "abiVersion",
            "protocolVersions",
            "minClientVersions",
            "platforms",
        ):
            assert required_key in manifest, f"missing key {required_key}"
        assert manifest["coreVersion"] == core_version
        assert manifest["gitCommit"] == "deadbeef"
        assert "ios" in manifest["platforms"]
        assert "android" in manifest["platforms"]
        assert "checksumsOnly" in manifest["platforms"]
        assert len(checksums) == 3

        # Conflict detection
        conflict_sums = tmp / "CONFLICT.txt"
        conflict_sums.write_text(
            f"{'d' * 64}  RabbitControlCore-{core_version}.xcframework.zip\n",
            encoding="utf-8",
        )
        try:
            build_manifest(
                repo_root,
                tag=f"v{core_version}",
                checksum_files=[sums_file, conflict_sums],
            )
        except ValueError:
            pass
        else:
            raise AssertionError("expected conflicting SHA256SUMS to raise ValueError")

        # Path traversal and leading dot/dash filename rejection
        for bad_name in ("../escape.tar.gz", ".hidden.tar.gz", "-flag.tar.gz"):
            try:
                parse_sha256sums_text(f"{apple_sha}  {bad_name}\n")
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"expected unsafe filename {bad_name!r} to be rejected"
                )

        # Boolean size must be rejected (in Python isinstance(True, int) is True)
        bool_size_frag = tmp / "bool_size.json"
        bool_size_frag.write_text(
            json.dumps(
                {
                    "platform": "linux",
                    "artifacts": [
                        {
                            "name": "rabbitcontrol-linux.tar.gz",
                            "sha256": extra_sha,
                            "size": True,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        try:
            build_manifest(
                repo_root,
                tag=f"v{core_version}",
                platform_manifest_files=[bool_size_frag],
            )
        except ValueError:
            pass
        else:
            raise AssertionError("expected boolean artifact size to be rejected")

    print(
        f"OK: build-release-manifest self-test passed "
        f"(core={core_version}, abi={meta['abiVersion']}, "
        f"proto={meta['protocolVersions']})."
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build or verify RabbitControl Core release-manifest.json."
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent,
        help="Path to rabbitcontrol-core repository root.",
    )
    parser.add_argument(
        "--verify-tag",
        type=str,
        default=None,
        help="Verify that the given Git tag (e.g. v0.2.2) matches workspace.package.version and exit.",
    )
    parser.add_argument(
        "--tag",
        type=str,
        default=None,
        help="Release Git tag to embed and verify against Cargo.toml.",
    )
    parser.add_argument(
        "--git-commit",
        type=str,
        default=None,
        help="Git commit SHA to embed (defaults to `git rev-parse HEAD`).",
    )
    parser.add_argument(
        "--min-client-version",
        action="append",
        default=[],
        help="Override minClientVersions entry as `<platform>=<semver>` (repeatable).",
    )
    parser.add_argument(
        "--checksums",
        action="append",
        type=pathlib.Path,
        default=[],
        help="Path to a SHA256SUMS.txt file to merge (repeatable).",
    )
    parser.add_argument(
        "--platform-manifest",
        action="append",
        type=pathlib.Path,
        default=[],
        help="Path to a platform artifact manifest JSON fragment to merge (repeatable).",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=pathlib.Path,
        default=None,
        help="Optional directory of release artifacts to hash and include.",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Output path for release-manifest.json (stdout if omitted).",
    )
    parser.add_argument(
        "--write-checksums",
        type=pathlib.Path,
        default=None,
        help="Optional output path for combined SHA256SUMS.txt.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline self-test suite and exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = args.repo_root.resolve()

    try:
        if args.self_test:
            return run_self_test(repo_root)

        if args.verify_tag is not None:
            version = read_workspace_version(repo_root)
            verify_tag_matches_version(args.verify_tag, version)
            print(f"OK: tag {args.verify_tag} matches Cargo.toml version {version}.")
            return 0

        overrides: dict[str, str] = {}
        for item in args.min_client_version:
            if "=" not in item:
                raise ValueError(
                    f"--min-client-version expects <platform>=<semver>, got {item!r}"
                )
            k, v = item.split("=", 1)
            overrides[k] = v

        manifest, checksums = build_manifest(
            repo_root,
            tag=args.tag,
            git_commit=args.git_commit,
            min_client_overrides=overrides,
            checksum_files=args.checksums,
            platform_manifest_files=args.platform_manifest,
            artifacts_dir=args.artifacts_dir,
        )

        serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized, encoding="utf-8")
        else:
            sys.stdout.write(serialized)

        if args.write_checksums is not None:
            args.write_checksums.parent.mkdir(parents=True, exist_ok=True)
            args.write_checksums.write_text(
                format_sha256sums(checksums), encoding="utf-8"
            )
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
