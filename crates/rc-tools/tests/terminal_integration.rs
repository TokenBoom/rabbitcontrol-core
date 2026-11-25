#![cfg(unix)]

use std::thread;
use std::time::{Duration, Instant};

use rc_tools::terminal::{
    TerminalClientEngine, TerminalEvent, TerminalHostEngine, TerminalSessionInfo,
    MAX_CONCURRENT_TERMINALS, MAX_TERMINAL_WIRE_FRAME_BYTES,
};

fn pump_once(
    client: &mut TerminalClientEngine,
    host: &mut TerminalHostEngine,
) -> Vec<TerminalEvent> {
    let mut events = Vec::new();
    for f in client.poll_outgoing(32) {
        assert!(f.len() <= MAX_TERMINAL_WIRE_FRAME_BYTES);
        host.handle_incoming(&f);
    }
    for f in host.poll_outgoing(32) {
        assert!(f.len() <= MAX_TERMINAL_WIRE_FRAME_BYTES);
        events.extend(client.handle_incoming(&f));
    }
    events
}

#[test]
fn real_unix_pty_echo_resize_and_exit_zero() {
    let mut client = TerminalClientEngine::new();
    let mut host = TerminalHostEngine::new();

    let term_id = client.open(80, 24);
    let mut opened = false;
    let mut output_acc = String::new();
    let mut exit_code = None;
    let mut sent_cmd = false;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && exit_code.is_none() {
        for ev in pump_once(&mut client, &mut host) {
            match ev {
                TerminalEvent::Opened {
                    term_id: tid,
                    ok,
                    title,
                    cwd,
                    error,
                    ..
                } => {
                    assert_eq!(tid, term_id);
                    assert!(ok, "pty open failed: {error:?}");
                    assert!(!title.is_empty());
                    assert!(!cwd.is_empty());
                    opened = true;
                    if !sent_cmd {
                        client.resize(term_id, 120, 40);
                        client.send_input(term_id, b"echo RC_PTY_HELLO && exit 0\n");
                        sent_cmd = true;
                    }
                }
                TerminalEvent::Output {
                    term_id: tid,
                    text_utf8_lossy,
                    ..
                } => {
                    assert_eq!(tid, term_id);
                    output_acc.push_str(&text_utf8_lossy);
                }
                TerminalEvent::Exited { term_id: tid, code } => {
                    assert_eq!(tid, term_id);
                    exit_code = Some(code);
                }
                TerminalEvent::SessionList { .. }
                | TerminalEvent::Attached { .. }
                | TerminalEvent::Renamed { .. }
                | TerminalEvent::FontList { .. }
                | TerminalEvent::FontReady { .. } => {}
            }
        }
        if exit_code.is_none() {
            thread::sleep(Duration::from_millis(10));
        }
    }

    assert!(opened, "expected Opened event");
    assert_eq!(
        exit_code,
        Some(0),
        "expected Exited(0), got output: {output_acc:?}"
    );
    assert!(
        output_acc.contains("RC_PTY_HELLO"),
        "expected RC_PTY_HELLO in terminal output, got: {output_acc:?}"
    );
    assert_eq!(host.active_count(), 0);
}

#[test]
fn terminal_host_enforces_max_concurrent_ptys_and_clean_drop() {
    let mut client = TerminalClientEngine::new();
    let mut host = TerminalHostEngine::new();

    let mut opened_ok = 0usize;
    let mut opened_err = 0usize;

    for _ in 0..=MAX_CONCURRENT_TERMINALS {
        client.open(80, 24);
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (opened_ok + opened_err) <= MAX_CONCURRENT_TERMINALS {
        for ev in pump_once(&mut client, &mut host) {
            if let TerminalEvent::Opened { ok, .. } = ev {
                if ok {
                    opened_ok += 1;
                } else {
                    opened_err += 1;
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(opened_ok, MAX_CONCURRENT_TERMINALS);
    assert_eq!(opened_err, 1);
    assert_eq!(host.active_count(), MAX_CONCURRENT_TERMINALS);

    // Dropping TerminalHostEngine must terminate all live shells promptly.
    let drop_start = Instant::now();
    drop(host);
    assert!(
        drop_start.elapsed() < Duration::from_secs(3),
        "TerminalHostEngine::drop took too long"
    );
}

#[test]
fn background_pty_detach_replay_rename_and_explicit_close() {
    let mut client = TerminalClientEngine::new();
    let mut host = TerminalHostEngine::new();

    client.open_background(80, 24, None);
    let mut created_id: Option<u32> = None;
    let mut created_name = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && created_id.is_none() {
        for ev in pump_once(&mut client, &mut host) {
            if let TerminalEvent::Opened {
                term_id,
                name,
                created_at_unix_sec,
                ok: true,
                ..
            } = ev
            {
                assert!(created_at_unix_sec > 0);
                created_id = Some(term_id);
                created_name = name;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    let term_id = created_id.expect("background session must open");
    assert_eq!(created_name, "session1");

    // Rename session and verify List returns updated name.
    client.rename(term_id, "build-worker".to_string());
    let mut renamed_ok = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !renamed_ok {
        for ev in pump_once(&mut client, &mut host) {
            if let TerminalEvent::Renamed {
                term_id: tid,
                name,
                ok: true,
                ..
            } = ev
            {
                assert_eq!(tid, term_id);
                assert_eq!(name, "build-worker");
                renamed_ok = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(renamed_ok, "rename event must succeed");

    // Write output while detached and drain in background for ~200ms before attaching.
    client.send_input(term_id, b"echo BG_SCROLLBACK_MARKER\n");
    for f in client.poll_outgoing(8) {
        host.handle_incoming(&f);
    }
    let drain_deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < drain_deadline {
        host.poll_background();
        thread::sleep(Duration::from_millis(20));
    }

    // Re-attach with a fresh client engine (simulating reopening W3 or reconnecting).
    let mut client2 = TerminalClientEngine::new();
    client2.list();
    let mut listed: Vec<TerminalSessionInfo> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && listed.is_empty() {
        for ev in pump_once(&mut client2, &mut host) {
            if let TerminalEvent::SessionList { sessions } = ev {
                listed = sessions;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].term_id, term_id);
    assert_eq!(listed[0].name, "build-worker");
    assert!(!listed[0].attached);

    client2.attach(term_id, 100, 30);
    let mut attached_ok = false;
    let mut replayed = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (!attached_ok || !replayed.contains("BG_SCROLLBACK_MARKER"))
    {
        for ev in pump_once(&mut client2, &mut host) {
            match ev {
                TerminalEvent::Attached {
                    term_id: tid,
                    session: Some(info),
                    ok: true,
                    ..
                } if tid == term_id => {
                    assert_eq!(info.name, "build-worker");
                    assert_eq!(info.cols, 100);
                    assert_eq!(info.rows, 30);
                    attached_ok = true;
                }
                TerminalEvent::Output {
                    term_id: tid,
                    text_utf8_lossy,
                    ..
                } if tid == term_id => {
                    replayed.push_str(&text_utf8_lossy);
                }
                _ => {}
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(attached_ok);
    assert!(
        replayed.contains("BG_SCROLLBACK_MARKER"),
        "expected scrollback replay, got: {replayed:?}"
    );

    // Detach must keep PTY alive; only explicit close terminates it.
    client2.detach(term_id);
    let _ = pump_once(&mut client2, &mut host);
    assert_eq!(host.active_count(), 1);

    client2.close(term_id);
    let mut exited = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !exited {
        for ev in pump_once(&mut client2, &mut host) {
            if matches!(ev, TerminalEvent::Exited { term_id: tid, .. } if tid == term_id) {
                exited = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(exited);
    assert_eq!(host.active_count(), 0);
}
