//! HTTP-level integration test for `login::run_device_flow`.
//!
//! Spins up a hand-rolled HTTP/1.1 server on a free port that mimics the
//! control-plane device-flow endpoints (`/auth/device/code` and
//! `/auth/device/token`) exactly enough to drive the client.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use orlop::login;

struct Server {
    addr: String,
    poll_count: Arc<AtomicUsize>,
    _join: thread::JoinHandle<()>,
}

/// Behaviour for how the mock server should reply to the first N
/// `/auth/device/token` polls before granting a token.
#[derive(Clone, Copy)]
enum PollBehaviour {
    /// Reply `authorization_pending` `pending` times, then 200.
    Pending(usize),
    /// Reply `slow_down` once, then 200.
    SlowDown,
    /// Reply `access_denied`.
    Denied,
    /// Reply `expired_token`.
    Expired,
}

fn start(behaviour: PollBehaviour) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let poll_count = Arc::new(AtomicUsize::new(0));
    let pc = Arc::clone(&poll_count);

    let join = thread::spawn(move || loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = rest.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).ok();
        }

        let (status, payload): (&str, String) = match (method.as_str(), path.as_str()) {
            ("POST", "/auth/device/code") => (
                "200 OK",
                r#"{"device_code":"DEV","user_code":"ORL-XYZ","verification_uri":"http://example/device","expires_in":300,"interval":1}"#.to_string(),
            ),
            ("POST", "/auth/device/token") => {
                let n = pc.fetch_add(1, Ordering::SeqCst);
                match behaviour {
                    PollBehaviour::Pending(pending) if n < pending => (
                        "400 Bad Request",
                        r#"{"error":"authorization_pending"}"#.to_string(),
                    ),
                    PollBehaviour::Pending(_) => (
                        "200 OK",
                        r#"{"access_token":"AT_OK","access_expires_at":"2026-04-30T13:00:00Z","refresh_token":"RT_OK","refresh_expires_at":"2026-05-30T12:00:00Z","control_plane_url":"http://control.example","token_type":"Bearer","expires_in":3600}"#
                            .to_string(),
                    ),
                    PollBehaviour::SlowDown if n == 0 => (
                        "400 Bad Request",
                        r#"{"error":"slow_down"}"#.to_string(),
                    ),
                    PollBehaviour::SlowDown => (
                        "200 OK",
                        r#"{"access_token":"AT_OK","access_expires_at":"2026-04-30T13:00:00Z","refresh_token":"RT_OK","refresh_expires_at":"2026-05-30T12:00:00Z","token_type":"Bearer","expires_in":3600}"#
                            .to_string(),
                    ),
                    PollBehaviour::Denied => (
                        "400 Bad Request",
                        r#"{"error":"access_denied"}"#.to_string(),
                    ),
                    PollBehaviour::Expired => (
                        "400 Bad Request",
                        r#"{"error":"expired_token"}"#.to_string(),
                    ),
                }
            }
            _ => ("404 Not Found", String::new()),
        };

        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        stream.write_all(response.as_bytes()).ok();
        stream.flush().ok();
    });

    Server {
        addr,
        poll_count,
        _join: join,
    }
}

#[test]
fn run_device_flow_succeeds_after_pending_polls() {
    let srv = start(PollBehaviour::Pending(2));
    let url = format!("http://{}", srv.addr);
    let mut sink = Vec::new();
    let creds = login::run_device_flow(&url, &mut sink).expect("flow ok");
    assert_eq!(creds.access_token, "AT_OK");
    assert_eq!(creds.refresh_token, "RT_OK");
    assert_eq!(creds.control_plane_url, "http://control.example");
    assert!(srv.poll_count.load(Ordering::SeqCst) >= 3);
    let stderr = String::from_utf8(sink).unwrap();
    assert!(stderr.contains("ORL-XYZ"), "stderr: {stderr}");
    assert!(stderr.contains("http://example/device"), "stderr: {stderr}");
}

#[test]
fn run_device_flow_handles_slow_down() {
    let srv = start(PollBehaviour::SlowDown);
    let url = format!("http://{}", srv.addr);
    let mut sink = Vec::new();
    let creds = login::run_device_flow(&url, &mut sink).expect("flow ok");
    assert_eq!(creds.access_token, "AT_OK");
}

#[test]
fn run_device_flow_reports_denied() {
    let srv = start(PollBehaviour::Denied);
    let url = format!("http://{}", srv.addr);
    let mut sink = Vec::new();
    let err = login::run_device_flow(&url, &mut sink).unwrap_err();
    assert!(format!("{err}").contains("approval denied"));
}

#[test]
fn run_device_flow_reports_expired() {
    let srv = start(PollBehaviour::Expired);
    let url = format!("http://{}", srv.addr);
    let mut sink = Vec::new();
    let err = login::run_device_flow(&url, &mut sink).unwrap_err();
    assert!(format!("{err}").contains("device code expired"));
}
