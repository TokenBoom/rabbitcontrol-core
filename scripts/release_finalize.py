#!/usr/bin/env python3
"""Atomic Cross-Repo Draft Release Orchestrator and Finalizer (stdlib-only Python 3).

Supports:
- `--ensure-draft-release`: idempotently locate or create a Draft GitHub Release for a tag
- `--upload-assets`: idempotently delete-and-upload assets to a release by release ID
- `--finalize`: verify all `platform-*.json` manifests and declared asset checksums/sizes
  via Draft-safe API endpoints, rebuild `release-manifest.json` and `SHA256SUMS.txt`,
  upload them idempotently, and auto-publish the Draft Release once all expected
  platforms are verified (when `--publish` is set)
- `--self-test`: comprehensive offline test suite using local `ThreadingHTTPServer` mocks
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import importlib.util
import json
import mimetypes
import os
import pathlib
import re
import socketserver
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_ASSET_DOWNLOAD_BYTES = 256 * 1024 * 1024  # 256 MiB
DEFAULT_API_TIMEOUT_SECONDS = 30
DEFAULT_DOWNLOAD_TIMEOUT_SECONDS = 120
MAX_REDIRECTS = 5
DOWNLOAD_CHUNK_SIZE = 65536

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_RE = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"
)
HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
PLATFORM_NAME_RE = re.compile(r"^[a-z0-9]+$")
PLATFORM_ASSET_RE = re.compile(r"^platform-([a-z0-9]+)\.json$")
NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def load_build_release_manifest() -> Any:
    module_path = pathlib.Path(__file__).resolve().with_name("build-release-manifest.py")
    if not module_path.is_file():
        raise RuntimeError(f"missing helper script: {module_path}")
    spec = importlib.util.spec_from_file_location("build_release_manifest", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_release_manifest"] = module
    spec.loader.exec_module(module)
    return module


def validate_repo(repo: str) -> str:
    cleaned = repo.strip()
    if not REPO_RE.match(cleaned) or ".." in cleaned:
        raise ValueError(f"invalid GitHub repository slug: {repo!r}")
    owner, name = cleaned.split("/", 1)
    if owner in (".", "..") or name in (".", ".."):
        raise ValueError(f"invalid GitHub repository slug: {repo!r}")
    return cleaned


def validate_tag(tag: str) -> str:
    cleaned = tag.strip()
    if not TAG_RE.match(cleaned):
        raise ValueError(
            f"invalid release tag {tag!r}: expected semver tag like v0.2.2"
        )
    return cleaned


def validate_commit40(commit: str) -> str:
    cleaned = commit.strip()
    if not HEX40_RE.match(cleaned):
        raise ValueError(f"invalid 40-char git commit SHA: {commit!r}")
    return cleaned.lower()


def validate_target_commitish(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in cleaned):
        raise ValueError(f"invalid target-commitish: {value!r}")
    return cleaned


def validate_expected_platforms(raw: str) -> set[str]:
    parts = [part.strip().lower() for part in raw.split(",") if part.strip()]
    if not parts:
        raise ValueError("--expected-platforms must specify at least one platform")
    for plat in parts:
        if not PLATFORM_NAME_RE.match(plat):
            raise ValueError(
                f"invalid platform name {plat!r} in --expected-platforms: expected lowercase alphanumeric"
            )
    return set(parts)


def guess_content_type(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".json"):
        return "application/json"
    if lower.endswith(".txt") or lower.endswith(".sha256"):
        return "text/plain; charset=utf-8"
    if lower.endswith(".tar.gz") or lower.endswith(".tgz") or lower.endswith(".gz"):
        return "application/gzip"
    if lower.endswith(".zip"):
        return "application/zip"
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def _strip_auth_headers(req: urllib.request.Request) -> None:
    for header_map in (req.headers, req.unredirected_hdrs):
        for key in list(header_map.keys()):
            if key.lower() == "authorization":
                del header_map[key]


class CrossHostAuthStrippingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that strips Authorization headers on cross-origin redirects."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        old_parts = urllib.parse.urlsplit(req.full_url)
        new_parts = urllib.parse.urlsplit(newurl)
        new_scheme = new_parts.scheme.lower()
        if new_scheme not in ("http", "https"):
            raise ValueError(f"refusing redirect to unsupported scheme: {newurl!r}")

        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None

        same_origin = (
            new_scheme == old_parts.scheme.lower()
            and new_parts.netloc.lower() == old_parts.netloc.lower()
        )
        if not same_origin:
            _strip_auth_headers(new_req)
        return new_req


class GitHubApiError(RuntimeError):
    """Raised when a GitHub REST API call fails with non-2xx or malformed response."""

    def __init__(self, status: int, url: str, body: str) -> None:
        snippet = body[:500].replace("\n", " ").strip()
        super().__init__(f"GitHub API HTTP {status} for {url}: {snippet}")
        self.status = status
        self.url = url
        self.body = body


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        api_base: str | None = None,
        upload_base: str | None = None,
        max_download_bytes: int = MAX_ASSET_DOWNLOAD_BYTES,
    ) -> None:
        cleaned_token = token.strip()
        if not cleaned_token:
            raise ValueError("GitHub token must not be empty (set GH_TOKEN or GITHUB_TOKEN)")
        self.token = cleaned_token
        self.api_base = (
            api_base or os.environ.get("GITHUB_API_URL") or "https://api.github.com"
        ).rstrip("/")
        self.upload_base = (
            upload_base
            or os.environ.get("GITHUB_UPLOAD_URL")
            or "https://uploads.github.com"
        ).rstrip("/")
        for label, base in (("api_base", self.api_base), ("upload_base", self.upload_base)):
            scheme = urllib.parse.urlsplit(base).scheme.lower()
            if scheme not in ("http", "https"):
                raise ValueError(f"invalid {label} URL scheme: {base!r}")
        self.max_download_bytes = max_download_bytes
        self.api_opener = urllib.request.build_opener(
            CrossHostAuthStrippingRedirectHandler()
        )

    def _base_headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        return {
            "Accept": accept,
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "rabbitcontrol-release-finalize/1.0",
        }

    def request_json(
        self,
        method: str,
        path_or_url: str,
        *,
        payload: dict[str, Any] | None = None,
        timeout: int = DEFAULT_API_TIMEOUT_SECONDS,
    ) -> tuple[int, Any, dict[str, str]]:
        url = (
            path_or_url
            if path_or_url.startswith(("http://", "https://"))
            else f"{self.api_base}{path_or_url}"
        )
        headers = self._base_headers()
        data: bytes | None = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(data))

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.api_opener.open(req, timeout=timeout) as resp:
                status = resp.getcode()
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise GitHubApiError(exc.code, url, err_body) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"network error calling {url}: {exc.reason}") from exc

        if not (200 <= status < 300):
            raise GitHubApiError(status, url, raw.decode("utf-8", errors="replace"))

        if not raw:
            return status, None, resp_headers
        return status, json.loads(raw.decode("utf-8")), resp_headers

    def get_paginated(self, path: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        sep = "&" if "?" in path else "?"
        next_url: str | None = f"{self.api_base}{path}{sep}per_page=100&page=1"
        page = 1
        while next_url:
            _, data, resp_headers = self.request_json("GET", next_url)
            if not isinstance(data, list):
                raise RuntimeError(f"expected list response from {next_url}, got {type(data).__name__}")
            for item in data:
                if isinstance(item, dict):
                    results.append(item)

            link_header = resp_headers.get("link", "")
            match = NEXT_LINK_RE.search(link_header)
            if match:
                next_url = match.group(1)
            elif len(data) == 100 and "link" not in resp_headers:
                page += 1
                next_url = f"{self.api_base}{path}{sep}per_page=100&page={page}"
            else:
                next_url = None
        return results

    def find_release_by_tag(self, repo: str, tag: str) -> dict[str, Any] | None:
        releases = self.get_paginated(f"/repos/{repo}/releases")
        for rel in releases:
            if rel.get("tag_name") == tag:
                return rel
        return None

    def get_release_by_id(self, repo: str, release_id: int) -> dict[str, Any]:
        _, data, _ = self.request_json("GET", f"/repos/{repo}/releases/{release_id}")
        if not isinstance(data, dict):
            raise RuntimeError(f"unexpected release payload for id {release_id}")
        return data

    def list_release_assets(self, repo: str, release_id: int) -> list[dict[str, Any]]:
        return self.get_paginated(f"/repos/{repo}/releases/{release_id}/assets")

    def create_draft_release(
        self,
        repo: str,
        tag: str,
        *,
        target_commitish: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tag_name": tag,
            "name": f"RabbitControl Core {tag}",
            "draft": True,
            "generate_release_notes": True,
        }
        if target_commitish:
            payload["target_commitish"] = target_commitish
        _, data, _ = self.request_json("POST", f"/repos/{repo}/releases", payload=payload)
        if not isinstance(data, dict):
            raise RuntimeError("unexpected create release response")
        return data

    def patch_release_publish(self, repo: str, release_id: int) -> dict[str, Any]:
        _, data, _ = self.request_json(
            "PATCH",
            f"/repos/{repo}/releases/{release_id}",
            payload={"draft": False},
        )
        if not isinstance(data, dict):
            raise RuntimeError("unexpected patch release response")
        return data

    def delete_asset(self, repo: str, asset_id: int) -> None:
        self.request_json("DELETE", f"/repos/{repo}/releases/assets/{asset_id}")

    def upload_asset(
        self,
        repo: str,
        release_id: int,
        file_path: pathlib.Path,
        asset_name: str,
        *,
        timeout: int = DEFAULT_DOWNLOAD_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        encoded_name = urllib.parse.quote(asset_name, safe="")
        url = f"{self.upload_base}/repos/{repo}/releases/{release_id}/assets?name={encoded_name}"
        raw = file_path.read_bytes()
        headers = self._base_headers()
        headers["Content-Type"] = guess_content_type(asset_name)
        headers["Content-Length"] = str(len(raw))
        req = urllib.request.Request(url, data=raw, headers=headers, method="POST")
        try:
            with self.api_opener.open(req, timeout=timeout) as resp:
                status = resp.getcode()
                body = resp.read()
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise GitHubApiError(exc.code, url, err_body) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"network error uploading {asset_name}: {exc.reason}") from exc

        if not (200 <= status < 300):
            raise GitHubApiError(status, url, body.decode("utf-8", errors="replace"))
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError(f"unexpected upload response for {asset_name}")
        return data

    def download_asset_to_file(
        self,
        repo: str,
        asset_id: int,
        dest_path: pathlib.Path,
        *,
        timeout: int = DEFAULT_DOWNLOAD_TIMEOUT_SECONDS,
    ) -> tuple[str, int]:
        """Download a Draft-safe release asset, enforcing size cap and cross-host auth stripping."""
        url = f"{self.api_base}/repos/{repo}/releases/assets/{asset_id}"
        headers = self._base_headers(accept="application/octet-stream")
        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with self.api_opener.open(req, timeout=timeout) as resp:
                status = resp.getcode()
                if not (200 <= status < 300):
                    body = resp.read(1024).decode("utf-8", errors="replace")
                    raise GitHubApiError(status, url, body)

                content_length_hdr = resp.headers.get("Content-Length")
                if content_length_hdr is not None:
                    try:
                        declared_len = int(content_length_hdr.strip())
                    except ValueError as exc:
                        raise ValueError(
                            f"invalid Content-Length header {content_length_hdr!r} for asset {asset_id}"
                        ) from exc
                    if declared_len > self.max_download_bytes:
                        raise ValueError(
                            f"asset {asset_id} exceeds max download size "
                            f"({declared_len} > {self.max_download_bytes})"
                        )

                digest = hashlib.sha256()
                total_bytes = 0
                with dest_path.open("wb") as out_fh:
                    while True:
                        chunk = resp.read(DOWNLOAD_CHUNK_SIZE)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > self.max_download_bytes:
                            raise ValueError(
                                f"asset {asset_id} download exceeded max size "
                                f"({self.max_download_bytes} bytes)"
                            )
                        digest.update(chunk)
                        out_fh.write(chunk)
                return digest.hexdigest(), total_bytes
        except urllib.error.HTTPError as exc:
            err_body = exc.read(1024).decode("utf-8", errors="replace")
            raise GitHubApiError(exc.code, url, err_body) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"network error downloading asset {asset_id}: {exc.reason}") from exc


def write_github_outputs(path: pathlib.Path | None, values: dict[str, str]) -> None:
    if path is None:
        return
    lines: list[str] = []
    for k, v in values.items():
        if "\n" in k or "\r" in k or "=" in k:
            raise ValueError(f"invalid GitHub output key: {k!r}")
        if "\n" in v or "\r" in v:
            raise ValueError(f"invalid multiline value for GitHub output {k!r}")
        lines.append(f"{k}={v}\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.writelines(lines)


def ensure_draft_release(
    client: GitHubClient,
    *,
    repo: str,
    tag: str,
    target_commitish: str | None = None,
    github_output: pathlib.Path | None = None,
) -> dict[str, Any]:
    existing = client.find_release_by_tag(repo, tag)
    if existing is not None:
        release = existing
        created = False
    else:
        release = client.create_draft_release(
            repo, tag, target_commitish=target_commitish
        )
        created = True

    release_id = release.get("id")
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id <= 0:
        raise RuntimeError(f"release missing valid integer id: {release!r}")

    draft_val = bool(release.get("draft", False))
    html_url = str(release.get("html_url") or "")
    write_github_outputs(
        github_output,
        {
            "release_id": str(release_id),
            "draft": "true" if draft_val else "false",
            "html_url": html_url,
        },
    )
    action = "created draft" if created else "found existing"
    print(
        f"OK: {action} release id={release_id} tag={tag} "
        f"draft={'true' if draft_val else 'false'} url={html_url}"
    )
    return release


def upload_assets(
    client: GitHubClient,
    *,
    repo: str,
    release_id: int,
    files: list[pathlib.Path],
) -> list[dict[str, Any]]:
    if release_id <= 0:
        raise ValueError(f"--release-id must be > 0, got {release_id}")
    if not files:
        raise ValueError("--upload-assets requires at least one --file")

    brm = load_build_release_manifest()
    validated_files: list[tuple[pathlib.Path, str]] = []
    seen_names: set[str] = set()
    for raw_path in files:
        if raw_path.is_symlink() or not raw_path.is_file():
            raise ValueError(f"upload file must be a regular non-symlink file: {raw_path}")
        asset_name = brm.validate_artifact_name(raw_path.name)
        if asset_name in seen_names:
            raise ValueError(f"duplicate asset filename in upload batch: {asset_name!r}")
        seen_names.add(asset_name)
        validated_files.append((raw_path, asset_name))

    # Verify release exists before replacing assets.
    client.get_release_by_id(repo, release_id)
    existing_assets = client.list_release_assets(repo, release_id)
    by_name = {
        str(a.get("name")): a
        for a in existing_assets
        if isinstance(a, dict) and a.get("name")
    }

    uploaded: list[dict[str, Any]] = []
    for file_path, asset_name in validated_files:
        existing = by_name.get(asset_name)
        if existing is not None:
            old_id = existing.get("id")
            if isinstance(old_id, int) and not isinstance(old_id, bool):
                print(f"Deleting existing asset {asset_name} (id={old_id}) before re-upload...")
                client.delete_asset(repo, old_id)
        print(f"Uploading {asset_name} ({file_path.stat().st_size} bytes) to release {release_id}...")
        uploaded.append(client.upload_asset(repo, release_id, file_path, asset_name))

    print(f"OK: uploaded {len(uploaded)} asset(s) to release {release_id}.")
    return uploaded


def resolve_release_for_finalize(
    client: GitHubClient,
    *,
    repo: str,
    tag: str,
    release_id: int | None = None,
) -> dict[str, Any]:
    release = client.find_release_by_tag(repo, tag)
    if release is None:
        raise ValueError(f"release for tag {tag!r} not found in {repo}")

    resolved_id = release.get("id")
    if isinstance(resolved_id, bool) or not isinstance(resolved_id, int) or resolved_id <= 0:
        raise ValueError(f"resolved release for tag {tag!r} has invalid id: {resolved_id!r}")

    if release_id is not None and release_id > 0:
        direct = client.get_release_by_id(repo, release_id)
        if direct.get("tag_name") != tag:
            raise ValueError(
                f"release {release_id} tag_name={direct.get('tag_name')!r} != {tag!r}"
            )
        if direct.get("id") != release_id or resolved_id != release_id:
            raise ValueError(
                f"release ID mismatch: tag {tag!r} resolved to {resolved_id}, expected {release_id}"
            )
        return direct
    return release


def finalize_release(
    client: GitHubClient,
    *,
    repo: str,
    tag: str,
    tag_commit: str,
    repo_root: pathlib.Path,
    expected_platforms: set[str],
    publish: bool = False,
    release_id: int | None = None,
    github_output: pathlib.Path | None = None,
) -> dict[str, Any]:
    brm = load_build_release_manifest()
    release = resolve_release_for_finalize(
        client, repo=repo, tag=tag, release_id=release_id
    )
    rid = int(release["id"])
    assets = client.list_release_assets(repo, rid)
    assets_by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        aname = asset.get("name")
        if isinstance(aname, str) and aname:
            assets_by_name[aname] = asset

    platform_assets: list[tuple[str, dict[str, Any]]] = []
    for aname in sorted(assets_by_name):
        if aname.startswith("platform-") and aname.endswith(".json"):
            m = PLATFORM_ASSET_RE.match(aname)
            if not m:
                raise ValueError(
                    f"invalid platform manifest asset name {aname!r}: "
                    "expected platform-<lowercase_alnum>.json"
                )
            platform_assets.append((m.group(1), assets_by_name[aname]))

    verified_platforms: set[str] = set()
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp_dir = pathlib.Path(tmp_str)
        downloaded_platform_files: list[pathlib.Path] = []

        for expected_plat_key, plat_asset in platform_assets:
            plat_asset_id = plat_asset.get("id")
            if isinstance(plat_asset_id, bool) or not isinstance(plat_asset_id, int):
                raise ValueError(f"platform asset {plat_asset.get('name')!r} missing id")

            local_frag_path = tmp_dir / str(plat_asset["name"])
            client.download_asset_to_file(repo, plat_asset_id, local_frag_path)
            frag = json.loads(local_frag_path.read_text(encoding="utf-8"))
            if not isinstance(frag, dict):
                raise ValueError(
                    f"platform manifest {plat_asset['name']!r} must be a JSON object"
                )

            frag_plat = frag.get("platform")
            if (
                not isinstance(frag_plat, str)
                or not PLATFORM_NAME_RE.match(frag_plat)
                or frag_plat != expected_plat_key
            ):
                raise ValueError(
                    f"platform manifest {plat_asset['name']!r} has invalid/mismatched "
                    f"platform={frag_plat!r} (expected {expected_plat_key!r})"
                )

            if frag_plat in verified_platforms:
                raise ValueError(f"duplicate platform manifest for {frag_plat!r}")

            frag_core_tag = frag.get("coreTag")
            if frag_core_tag != tag:
                raise ValueError(
                    f"{plat_asset['name']} coreTag mismatch: {frag_core_tag!r} != {tag!r}"
                )

            if "coreCommit" in frag and frag["coreCommit"] is not None:
                core_commit_raw = frag["coreCommit"]
                if not isinstance(core_commit_raw, str):
                    raise ValueError(
                        f"{plat_asset['name']} coreCommit must be a string"
                    )
                if core_commit_raw.strip():
                    if core_commit_raw.strip().lower() != tag_commit.lower():
                        raise ValueError(
                            f"{plat_asset['name']} coreCommit mismatch: "
                            f"{core_commit_raw!r} != {tag_commit!r}"
                        )

            artifacts = frag.get("artifacts")
            if not isinstance(artifacts, list) or not artifacts:
                raise ValueError(
                    f"{plat_asset['name']} must declare a non-empty 'artifacts' list"
                )

            for idx, art in enumerate(artifacts):
                if not isinstance(art, dict):
                    raise ValueError(
                        f"{plat_asset['name']} artifacts[{idx}] must be an object"
                    )
                art_name = brm.validate_artifact_name(str(art.get("name", "")))
                expected_sha = brm.validate_sha256(str(art.get("sha256", "")))
                declared_size = art.get("size")
                if (
                    isinstance(declared_size, bool)
                    or not isinstance(declared_size, int)
                    or declared_size < 0
                ):
                    raise ValueError(
                        f"{plat_asset['name']} artifact {art_name!r} missing valid integer 'size'"
                    )

                rel_asset = assets_by_name.get(art_name)
                if rel_asset is None:
                    raise ValueError(
                        f"{plat_asset['name']} references missing release asset {art_name!r}"
                    )
                rel_asset_size = rel_asset.get("size")
                if (
                    isinstance(rel_asset_size, bool)
                    or not isinstance(rel_asset_size, int)
                    or rel_asset_size != declared_size
                ):
                    raise ValueError(
                        f"asset {art_name!r} size mismatch: release has {rel_asset_size!r}, "
                        f"{plat_asset['name']} declares {declared_size!r}"
                    )
                rel_asset_id = rel_asset.get("id")
                if isinstance(rel_asset_id, bool) or not isinstance(rel_asset_id, int):
                    raise ValueError(f"release asset {art_name!r} missing valid id")

                art_tmp = tmp_dir / f"verify-{art_name}"
                actual_sha, actual_size = client.download_asset_to_file(
                    repo, rel_asset_id, art_tmp
                )
                art_tmp.unlink(missing_ok=True)
                if actual_size != declared_size:
                    raise ValueError(
                        f"downloaded asset {art_name!r} byte length mismatch: "
                        f"got {actual_size}, expected {declared_size}"
                    )
                if actual_sha != expected_sha:
                    raise ValueError(
                        f"downloaded asset {art_name!r} SHA-256 mismatch: "
                        f"got {actual_sha}, expected {expected_sha}"
                    )

            verified_platforms.add(frag_plat)
            downloaded_platform_files.append(local_frag_path)

        manifest, checksums = brm.build_manifest(
            repo_root,
            tag=tag,
            git_commit=tag_commit,
            platform_manifest_files=downloaded_platform_files,
        )
        if "checksumsOnly" in manifest.get("platforms", {}):
            raise RuntimeError("unexpected checksumsOnly section in finalized manifest")

        manifest_path = tmp_dir / "release-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        sums_path = tmp_dir / "SHA256SUMS.txt"
        sums_path.write_text(brm.format_sha256sums(checksums), encoding="utf-8")

        upload_assets(
            client,
            repo=repo,
            release_id=rid,
            files=[manifest_path, sums_path],
        )

    missing_platforms = sorted(expected_platforms - verified_platforms)
    is_draft = bool(release.get("draft", False))
    published_now = False
    if publish and is_draft and not missing_platforms:
        updated = client.patch_release_publish(repo, rid)
        is_draft = bool(updated.get("draft", False))
        published_now = not is_draft
        release = updated
    elif missing_platforms:
        print(
            f"Waiting for remaining expected platform(s): {', '.join(missing_platforms)} "
            f"(verified: {', '.join(sorted(verified_platforms)) or 'none'}; "
            f"draft={'true' if is_draft else 'false'})"
        )
    elif not is_draft:
        print(
            f"Release {rid} ({tag}) is already published; backfilled manifest without modifying draft state."
        )

    html_url = str(release.get("html_url") or "")
    write_github_outputs(
        github_output,
        {
            "release_id": str(rid),
            "draft": "true" if is_draft else "false",
            "published_now": "true" if published_now else "false",
            "verified_platforms": ",".join(sorted(verified_platforms)),
            "missing_platforms": ",".join(missing_platforms),
            "html_url": html_url,
        },
    )
    print(
        f"OK: finalized release id={rid} tag={tag} "
        f"verified=[{','.join(sorted(verified_platforms))}] "
        f"missing=[{','.join(missing_platforms)}] "
        f"draft={'true' if is_draft else 'false'}"
    )
    return {
        "release": release,
        "manifest": manifest,
        "verified_platforms": sorted(verified_platforms),
        "missing_platforms": missing_platforms,
        "published_now": published_now,
    }


# ---------------------------------------------------------------------------
# Offline self-test suite with mock GitHub API + cross-host CDN redirector
# ---------------------------------------------------------------------------


class _MockGitHubState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.next_release_id = 100
        self.next_asset_id = 1000
        self.releases: dict[int, dict[str, Any]] = {}
        self.asset_blobs: dict[int, bytes] = {}
        self.asset_content_types: dict[int, str] = {}
        self.api_auth_headers_seen: list[str | None] = []
        self.cdn_auth_headers_seen: list[str | None] = []
        self.patch_payloads: list[dict[str, Any]] = []
        self.cdn_base_url: str = ""
        self.api_base_url: str = ""

    def find_asset(self, asset_id: int) -> tuple[dict[str, Any], dict[str, Any]] | None:
        for rel in self.releases.values():
            for asset in rel["assets"]:
                if asset["id"] == asset_id:
                    return rel, asset
        return None


def _start_mock_servers() -> tuple[
    _MockGitHubState,
    socketserver.ThreadingMixIn,
    socketserver.ThreadingMixIn,
]:
    state = _MockGitHubState()

    class CdnHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlsplit(self.path)
            auth = self.headers.get("Authorization")
            with state.lock:
                state.cdn_auth_headers_seen.append(auth)
            if not parsed.path.startswith("/blobs/"):
                self.send_response(404)
                self.end_headers()
                return
            try:
                asset_id = int(parsed.path.rsplit("/", 1)[-1])
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            with state.lock:
                blob = state.asset_blobs.get(asset_id)
            if blob is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    class ApiHandler(http.server.BaseHTTPRequestHandler):
        def _send_json(self, code: int, obj: Any) -> None:
            raw = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(length) if length > 0 else b""

        def _check_auth(self) -> bool:
            auth = self.headers.get("Authorization")
            with state.lock:
                state.api_auth_headers_seen.append(auth)
            if auth != "Bearer test-secret-token":
                self._send_json(401, {"message": "Bad credentials"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._check_auth():
                return
            parsed = urllib.parse.urlsplit(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            path = parsed.path

            # Simulate real GitHub: /releases/tags/{tag} returns 404 for Drafts!
            m_tag = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases/tags/(.+)", path)
            if m_tag:
                tag = urllib.parse.unquote(m_tag.group(2))
                with state.lock:
                    for rel in state.releases.values():
                        if rel["tag_name"] == tag and not rel["draft"]:
                            self._send_json(200, rel)
                            return
                self._send_json(404, {"message": "Not Found"})
                return

            m_list = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases", path)
            if m_list:
                page = int(qs.get("page", ["1"])[0])
                per_page = int(qs.get("per_page", ["100"])[0])
                with state.lock:
                    all_rels = [
                        rel
                        for _, rel in sorted(state.releases.items(), reverse=True)
                    ]
                start = (page - 1) * per_page
                chunk = all_rels[start : start + per_page]
                self._send_json(200, chunk)
                return

            m_rel = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases/([0-9]+)", path)
            if m_rel:
                rid = int(m_rel.group(2))
                with state.lock:
                    rel = state.releases.get(rid)
                if rel is None:
                    self._send_json(404, {"message": "Not Found"})
                    return
                self._send_json(200, rel)
                return

            m_assets = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases/([0-9]+)/assets", path)
            if m_assets:
                rid = int(m_assets.group(2))
                page = int(qs.get("page", ["1"])[0])
                per_page = int(qs.get("per_page", ["100"])[0])
                with state.lock:
                    rel = state.releases.get(rid)
                    assets = list(rel["assets"]) if rel else None
                if assets is None:
                    self._send_json(404, {"message": "Not Found"})
                    return
                start = (page - 1) * per_page
                self._send_json(200, assets[start : start + per_page])
                return

            m_asset_dl = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases/assets/([0-9]+)", path)
            if m_asset_dl:
                aid = int(m_asset_dl.group(2))
                accept = self.headers.get("Accept", "")
                with state.lock:
                    found = state.find_asset(aid)
                    cdn_base = state.cdn_base_url
                if found is None:
                    self._send_json(404, {"message": "Not Found"})
                    return
                if "application/octet-stream" in accept:
                    # Cross-host redirect to CDN server (must strip Authorization header!).
                    self.send_response(302)
                    self.send_header("Location", f"{cdn_base}/blobs/{aid}")
                    self.end_headers()
                    return
                self._send_json(200, found[1])
                return

            self._send_json(404, {"message": f"Unknown GET path: {path}"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._check_auth():
                return
            parsed = urllib.parse.urlsplit(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            path = parsed.path

            m_create = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases", path)
            if m_create:
                repo = m_create.group(1)
                payload = json.loads(self._read_body().decode("utf-8"))
                with state.lock:
                    state.next_release_id += 1
                    rid = state.next_release_id
                    rel = {
                        "id": rid,
                        "tag_name": payload["tag_name"],
                        "target_commitish": payload.get("target_commitish", "main"),
                        "name": payload.get("name", payload["tag_name"]),
                        "body": "Generated notes",
                        "draft": bool(payload.get("draft", False)),
                        "html_url": f"https://github.com/{repo}/releases/tag/{payload['tag_name']}",
                        "assets": [],
                    }
                    state.releases[rid] = rel
                self._send_json(201, rel)
                return

            m_upload = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases/([0-9]+)/assets", path)
            if m_upload:
                rid = int(m_upload.group(2))
                asset_name = qs.get("name", [""])[0]
                blob = self._read_body()
                ctype = self.headers.get("Content-Type", "application/octet-stream")
                with state.lock:
                    rel = state.releases.get(rid)
                    if rel is None:
                        self._send_json(404, {"message": "Not Found"})
                        return
                    for existing in rel["assets"]:
                        if existing["name"] == asset_name:
                            self._send_json(422, {"message": "already_exists"})
                            return
                    state.next_asset_id += 1
                    aid = state.next_asset_id
                    asset_obj = {
                        "id": aid,
                        "name": asset_name,
                        "size": len(blob),
                        "content_type": ctype,
                    }
                    rel["assets"].append(asset_obj)
                    state.asset_blobs[aid] = blob
                    state.asset_content_types[aid] = ctype
                self._send_json(201, asset_obj)
                return

            self._send_json(404, {"message": f"Unknown POST path: {path}"})

        def do_PATCH(self) -> None:  # noqa: N802
            if not self._check_auth():
                return
            parsed = urllib.parse.urlsplit(self.path)
            m_patch = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases/([0-9]+)", parsed.path)
            if m_patch:
                rid = int(m_patch.group(2))
                payload = json.loads(self._read_body().decode("utf-8"))
                with state.lock:
                    state.patch_payloads.append(payload)
                    rel = state.releases.get(rid)
                    if rel is None:
                        self._send_json(404, {"message": "Not Found"})
                        return
                    for k in ("draft", "name", "body"):
                        if k in payload:
                            rel[k] = payload[k]
                self._send_json(200, rel)
                return
            self._send_json(404, {"message": f"Unknown PATCH path: {parsed.path}"})

        def do_DELETE(self) -> None:  # noqa: N802
            if not self._check_auth():
                return
            parsed = urllib.parse.urlsplit(self.path)
            m_del = re.fullmatch(r"/repos/([^/]+/[^/]+)/releases/assets/([0-9]+)", parsed.path)
            if m_del:
                aid = int(m_del.group(2))
                with state.lock:
                    found = state.find_asset(aid)
                    if found is None:
                        self._send_json(404, {"message": "Not Found"})
                        return
                    rel, asset = found
                    rel["assets"] = [a for a in rel["assets"] if a["id"] != aid]
                    state.asset_blobs.pop(aid, None)
                self.send_response(204)
                self.end_headers()
                return
            self._send_json(404, {"message": f"Unknown DELETE path: {parsed.path}"})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    class _ReusableThreadingHTTPServer(http.server.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    api_srv = _ReusableThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
    cdn_srv = _ReusableThreadingHTTPServer(("127.0.0.1", 0), CdnHandler)
    state.api_base_url = f"http://127.0.0.1:{api_srv.server_address[1]}"
    state.cdn_base_url = f"http://127.0.0.1:{cdn_srv.server_address[1]}"

    threading.Thread(target=api_srv.serve_forever, daemon=True).start()
    threading.Thread(target=cdn_srv.serve_forever, daemon=True).start()
    return state, api_srv, cdn_srv


def run_self_test(repo_root: pathlib.Path) -> int:
    brm = load_build_release_manifest()
    meta = brm.read_core_metadata(repo_root)
    core_version = meta["coreVersion"]
    tag = f"v{core_version}"
    tag_commit = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    repo = "TokenBoom/rabbitcontrol-core"

    # Validate input validators.
    assert validate_repo(repo) == repo
    assert validate_tag(tag) == tag
    assert validate_commit40(tag_commit.upper()) == tag_commit
    assert validate_expected_platforms("ios, android") == {"ios", "android"}
    for bad_repo in ("onlyowner", "../evil/repo", "a/b/c"):
        try:
            validate_repo(bad_repo)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected bad repo {bad_repo!r} to fail")
    for bad_tag in ("0.2.2", "v1.2", "v1.2.3;rm -rf /"):
        try:
            validate_tag(bad_tag)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected bad tag {bad_tag!r} to fail")

    state, api_srv, cdn_srv = _start_mock_servers()
    try:
        client = GitHubClient(
            "test-secret-token",
            api_base=state.api_base_url,
            upload_base=state.api_base_url,
        )

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            gh_out = tmp / "github_output.txt"

            # (a) Ensure Draft Release creates draft & preserves existing release body/state.
            rel1 = ensure_draft_release(
                client,
                repo=repo,
                tag=tag,
                target_commitish=tag_commit,
                github_output=gh_out,
            )
            rid = int(rel1["id"])
            assert rel1["draft"] is True
            state.releases[rid]["body"] = "Custom hand-edited notes"

            rel1_again = ensure_draft_release(
                client, repo=repo, tag=tag, target_commitish=tag_commit
            )
            assert rel1_again["id"] == rid
            assert rel1_again["draft"] is True
            assert rel1_again["body"] == "Custom hand-edited notes"

            # (b) Idempotent delete+upload replacing existing assets.
            ios_blob_v1 = b"ios-xcframework-v1"
            ios_blob = b"ios-xcframework-binary-payload-v2"
            ios_name = "RabbitControlCore.xcframework.tar.gz"
            ios_bin = tmp / ios_name
            ios_bin.write_bytes(ios_blob_v1)
            upload_assets(client, repo=repo, release_id=rid, files=[ios_bin])
            assert len(state.releases[rid]["assets"]) == 1
            old_aid = state.releases[rid]["assets"][0]["id"]

            ios_bin.write_bytes(ios_blob)
            upload_assets(client, repo=repo, release_id=rid, files=[ios_bin])
            assert len(state.releases[rid]["assets"]) == 1
            new_aid = state.releases[rid]["assets"][0]["id"]
            assert new_aid != old_aid
            assert state.asset_blobs[new_aid] == ios_blob
            assert state.asset_content_types[new_aid] == "application/gzip"

            # (c) Draft asset download with cross-host redirect stripping Authorization.
            dl_dest = tmp / "downloaded-ios.bin"
            dl_sha, dl_len = client.download_asset_to_file(repo, new_aid, dl_dest)
            ios_sha = hashlib.sha256(ios_blob).hexdigest()
            assert dl_sha == ios_sha
            assert dl_len == len(ios_blob)
            assert state.api_auth_headers_seen and all(
                h == "Bearer test-secret-token" for h in state.api_auth_headers_seen
            )
            assert state.cdn_auth_headers_seen and all(
                h is None for h in state.cdn_auth_headers_seen
            ), f"Authorization leaked on cross-host redirect: {state.cdn_auth_headers_seen}"

            # Enforce max download size guard.
            tiny_client = GitHubClient(
                "test-secret-token",
                api_base=state.api_base_url,
                upload_base=state.api_base_url,
                max_download_bytes=8,
            )
            try:
                tiny_client.download_asset_to_file(repo, new_aid, tmp / "too-big.bin")
            except ValueError:
                pass
            else:
                raise AssertionError("expected max_download_bytes check to fail")

            # Prepare valid platform-ios.json
            ios_manifest_path = tmp / "platform-ios.json"
            ios_manifest_obj = {
                "platform": "ios",
                "repo": "TokenBoom/rabbitcontrol-apple-media",
                "coreTag": tag,
                "coreCommit": tag_commit,
                "artifacts": [
                    {
                        "name": ios_name,
                        "sha256": ios_sha,
                        "size": len(ios_blob),
                        "arch": "universal",
                    }
                ],
            }
            ios_manifest_path.write_text(
                json.dumps(ios_manifest_obj), encoding="utf-8"
            )
            upload_assets(client, repo=repo, release_id=rid, files=[ios_manifest_path])

            # (e) Partial platform (ios only when expecting ios,android) keeps draft=true and uploads manifest+sums.
            res_partial = finalize_release(
                client,
                repo=repo,
                tag=tag,
                tag_commit=tag_commit,
                repo_root=repo_root,
                expected_platforms={"ios", "android"},
                publish=True,
                release_id=rid,
            )
            assert res_partial["release"]["draft"] is True
            assert res_partial["verified_platforms"] == ["ios"]
            assert res_partial["missing_platforms"] == ["android"]
            asset_names = {a["name"] for a in state.releases[rid]["assets"]}
            assert "release-manifest.json" in asset_names
            assert "SHA256SUMS.txt" in asset_names
            assert "checksumsOnly" not in res_partial["manifest"]["platforms"]

            # (d) Reject coreTag mismatch, coreCommit mismatch, asset size mismatch, SHA-256 tamper.
            def _assert_finalize_fails(mutated_obj: dict[str, Any], desc: str) -> None:
                ios_manifest_path.write_text(
                    json.dumps(mutated_obj), encoding="utf-8"
                )
                upload_assets(client, repo=repo, release_id=rid, files=[ios_manifest_path])
                try:
                    finalize_release(
                        client,
                        repo=repo,
                        tag=tag,
                        tag_commit=tag_commit,
                        repo_root=repo_root,
                        expected_platforms={"ios", "android"},
                        publish=True,
                        release_id=rid,
                    )
                except ValueError:
                    pass
                else:
                    raise AssertionError(f"expected finalize failure for {desc}")

            bad_tag_obj = dict(ios_manifest_obj, coreTag="v99.99.99")
            _assert_finalize_fails(bad_tag_obj, "coreTag mismatch")

            bad_commit_obj = dict(ios_manifest_obj, coreCommit="0" * 40)
            _assert_finalize_fails(bad_commit_obj, "coreCommit mismatch")

            bad_size_obj = json.loads(json.dumps(ios_manifest_obj))
            bad_size_obj["artifacts"][0]["size"] = len(ios_blob) + 1
            _assert_finalize_fails(bad_size_obj, "asset size mismatch")

            bad_sha_obj = json.loads(json.dumps(ios_manifest_obj))
            bad_sha_obj["artifacts"][0]["sha256"] = "f" * 64
            _assert_finalize_fails(bad_sha_obj, "SHA-256 tamper")

            # Restore valid platform-ios.json.
            ios_manifest_path.write_text(
                json.dumps(ios_manifest_obj), encoding="utf-8"
            )
            upload_assets(client, repo=repo, release_id=rid, files=[ios_manifest_path])

            # (f) Full platforms (ios + android) auto-publishes Draft while preserving body.
            android_blob = b"android-aar-binary-payload-v1"
            android_name = f"rabbitcontrol-core-{core_version}.aar"
            android_bin = tmp / android_name
            android_bin.write_bytes(android_blob)
            android_sha = hashlib.sha256(android_blob).hexdigest()

            android_manifest_path = tmp / "platform-android.json"
            android_manifest_path.write_text(
                json.dumps(
                    {
                        "platform": "android",
                        "repo": "TokenBoom/rabbitcontrol-android",
                        "coreTag": tag,
                        "coreCommit": tag_commit.upper(),
                        "artifacts": [
                            {
                                "name": android_name,
                                "sha256": android_sha,
                                "size": len(android_blob),
                                "arch": "arm64-v8a",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            upload_assets(
                client,
                repo=repo,
                release_id=rid,
                files=[android_bin, android_manifest_path],
            )

            res_full = finalize_release(
                client,
                repo=repo,
                tag=tag,
                tag_commit=tag_commit,
                repo_root=repo_root,
                expected_platforms={"ios", "android"},
                publish=True,
                release_id=rid,
                github_output=gh_out,
            )
            assert res_full["release"]["draft"] is False
            assert res_full["release"]["body"] == "Custom hand-edited notes"
            assert res_full["published_now"] is True
            assert res_full["verified_platforms"] == ["android", "ios"]
            assert res_full["missing_platforms"] == []
            assert state.patch_payloads[-1] == {"draft": False}
            assert "ios" in res_full["manifest"]["platforms"]
            assert "android" in res_full["manifest"]["platforms"]

            # Backfill already-published release: must NOT revert to draft or overwrite body.
            patches_before = len(state.patch_payloads)
            res_backfill = finalize_release(
                client,
                repo=repo,
                tag=tag,
                tag_commit=tag_commit,
                repo_root=repo_root,
                expected_platforms={"ios", "android"},
                publish=True,
                release_id=rid,
            )
            assert res_backfill["release"]["draft"] is False
            assert res_backfill["release"]["body"] == "Custom hand-edited notes"
            assert res_backfill["published_now"] is False
            assert len(state.patch_payloads) == patches_before

            # ensure_draft_release on already-published release must preserve draft=false and body.
            rel_existing_pub = ensure_draft_release(client, repo=repo, tag=tag)
            assert rel_existing_pub["draft"] is False
            assert rel_existing_pub["body"] == "Custom hand-edited notes"
    finally:
        api_srv.shutdown()
        api_srv.server_close()
        cdn_srv.shutdown()
        cdn_srv.server_close()

    print(
        f"OK: release_finalize self-test passed "
        f"(tag={tag}, cross-host auth stripping, tamper guards, partial+publish+backfill)."
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Draft-safe GitHub Release orchestrator and finalizer."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--ensure-draft-release",
        action="store_true",
        help="Ensure a Draft Release exists for --tag (preserving existing releases).",
    )
    mode.add_argument(
        "--upload-assets",
        action="store_true",
        help="Idempotently replace and upload --file assets to --release-id.",
    )
    mode.add_argument(
        "--finalize",
        action="store_true",
        help="Verify platform-*.json manifests and assets, rebuild manifest, and optionally publish.",
    )
    mode.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline self-test suite against local mock HTTP servers.",
    )

    parser.add_argument("--repo", type=str, help="GitHub repository (<owner>/<name>).")
    parser.add_argument("--tag", type=str, help="Release Git tag (e.g. v0.2.2).")
    parser.add_argument(
        "--target-commitish",
        type=str,
        default=None,
        help="Target commit SHA or branch when creating a new Draft Release.",
    )
    parser.add_argument(
        "--release-id",
        type=int,
        default=None,
        help="GitHub Release ID (required for --upload-assets; optional cross-check for --finalize).",
    )
    parser.add_argument(
        "--file",
        dest="files",
        action="extend",
        nargs="+",
        type=pathlib.Path,
        default=[],
        help="Asset file path(s) to upload with --upload-assets.",
    )
    parser.add_argument(
        "--tag-commit",
        type=str,
        help="Expected 40-char hex commit SHA for --tag (required for --finalize).",
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent,
        help="Path to rabbitcontrol-core repository/worktree root.",
    )
    parser.add_argument(
        "--expected-platforms",
        type=str,
        default="ios,android",
        help="Comma-separated expected platform names required before --publish.",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish Draft Release (draft -> false) if all expected platforms are verified.",
    )
    parser.add_argument(
        "--github-output",
        type=pathlib.Path,
        default=None,
        help="Optional GITHUB_OUTPUT file path to append key=value outputs.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.self_test:
            return run_self_test(args.repo_root.resolve())

        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
        client = GitHubClient(token)

        if not args.repo:
            raise ValueError("--repo is required")
        repo = validate_repo(args.repo)

        if args.ensure_draft_release:
            if not args.tag:
                raise ValueError("--tag is required for --ensure-draft-release")
            tag = validate_tag(args.tag)
            commitish = validate_target_commitish(args.target_commitish)
            ensure_draft_release(
                client,
                repo=repo,
                tag=tag,
                target_commitish=commitish,
                github_output=args.github_output,
            )
            return 0

        if args.upload_assets:
            if args.release_id is None or args.release_id <= 0:
                raise ValueError("--release-id (> 0) is required for --upload-assets")
            upload_assets(
                client,
                repo=repo,
                release_id=args.release_id,
                files=args.files,
            )
            return 0

        if args.finalize:
            if not args.tag:
                raise ValueError("--tag is required for --finalize")
            if not args.tag_commit:
                raise ValueError("--tag-commit is required for --finalize")
            tag = validate_tag(args.tag)
            tag_commit = validate_commit40(args.tag_commit)
            expected_platforms = validate_expected_platforms(args.expected_platforms)
            if args.release_id is not None and args.release_id < 0:
                raise ValueError("--release-id must not be negative")
            finalize_release(
                client,
                repo=repo,
                tag=tag,
                tag_commit=tag_commit,
                repo_root=args.repo_root.resolve(),
                expected_platforms=expected_platforms,
                publish=bool(args.publish),
                release_id=args.release_id if args.release_id and args.release_id > 0 else None,
                github_output=args.github_output,
            )
            return 0

        raise ValueError("no action specified")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, GitHubApiError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
