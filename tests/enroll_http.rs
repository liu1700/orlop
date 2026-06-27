//! HTTP-level integration test for `enroll::enroll`.
//!
//! Spins up a hand-rolled HTTP/1.1 server on a free port that mimics the
//! control-plane `/agent/enroll` endpoint exactly enough to exercise the
//! happy path, the 401 / 403 / 503-with-Retry-After branches, and the
//! cert-file persistence side effects. mTLS dial against `orlop-server` is
//! covered by the issue's manual smoke (`tcpdump`) and a future end-to-end smoke test; plain HTTP is enough here because the
//! enroll client only speaks the `/agent/enroll` JSON API.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use chrono::Utc;
use orlop::enroll;
use orlop::login::Credentials;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("orlop-enroll-it-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Behaviour {
    /// Always return 200 with a successful enrollment payload.
    Success,
    /// Return 401 unauthorized.
    Unauthorized,
    /// Return 403 forbidden.
    Forbidden,
    /// First call: 503 with Retry-After: 1; subsequent: 200.
    RetryThenSuccess,
    /// Always 503.
    AlwaysUnavailable,
}

struct Server {
    addr: String,
    request_count: Arc<AtomicUsize>,
    last_authorization: Arc<parking_lot::Mutex<Option<String>>>,
    _join: thread::JoinHandle<()>,
}

const SAMPLE_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIBDTANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhhZGct
dGVzdDAeFw0yNjA0MzAwMjA0MzJaFw0yNjA1MDEwMjA0MzJaMBMxETAPBgNVBAMM
CGFkZy10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouvBzEGc
sh6si4RXMvEGFKnpiFo6ekW9juNCd9a11iXUHDSNsxgIOVxExqIgFcRytDkWEquG
3YAH+H/dy1010BLhJAH9yMaW3XI3/Un2HMq+jG1Jpm4GzJodDGsTwSzibzp4gEsL
46yqoz+yAp+/L128OL1/RkBOP62OxlMce21lnLOTt6eAt6xiJD0A/E3gPzsc/9iA
g6tLrVuZjm2TfYh+6b0hHqI6zfKcp2VUv783o21GIQW2Qv7TGgP+tFg1fAWgW89X
SVqSiq3WG9+X0ytg65N2DAv/ejVU/7z/zwikDnvu6jH7nB3dTZmF6w5Gt2/KPtiN
BVR40QZRjcdC7wIDAQABo1MwUTAdBgNVHQ4EFgQUnx+cZJZ4rzPoYTturQGp2soW
UIIwHwYDVR0jBBgwFoAUnx+cZJZ4rzPoYTturQGp2soWUIIwDwYDVR0TAQH/BAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAIvhRVdf5OFVAHvHjBghwMKHpf1cUL2Or
lGtPZ/A/0nZnSDSUoxPuom3BNu/oBb9jrK+epXVEMWdJXf1yO11CQiQy3DrgI1Dn
HIOUFUnsnPX+AhxZfadX6LW6P6k11slE+FqhqDyZy7NC5du0L2KU4ehdsrd0jNVy
/+I0PRgZMY19kopjcHWgGGSm7lXmHofg+IvgxkYRFfxEG420Tuw/yZ4icj9L8m9B
RRntjQih7hTQLClxC88VzCOIZo1yGc57P+o5LU0OfB82xEWHhGXUDQjtqaoANjPw
gz6ouG0MNrc8wNu++RoOct9R7cQmNOQvk+4qQCEYZXiqKwffFEz0xg==
-----END CERTIFICATE-----
";

fn success_body() -> String {
    let cert = SAMPLE_CERT.replace('\n', "\\n");
    let key = "-----BEGIN PRIVATE KEY-----\\nMIIFAKE\\n-----END PRIVATE KEY-----\\n";
    let ca = "-----BEGIN CERTIFICATE-----\\nMIICA\\n-----END CERTIFICATE-----\\n";
    format!(
        r#"{{"client_cert_pem":"{cert}","client_key_pem":"{key}","ca_chain_pem":"{ca}","server_addr":"tenant-acme.orlop.example.com","expires_at":"2026-04-30T03:00:00Z","allocation_id":"alloc_test","size_bytes":5368709120}}"#,
    )
}

fn start(behaviour: Behaviour) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let request_count = Arc::new(AtomicUsize::new(0));
    let rc = Arc::clone(&request_count);
    let last_auth: Arc<parking_lot::Mutex<Option<String>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let last_auth_writer = Arc::clone(&last_auth);

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
        let mut auth: Option<String> = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || line.is_empty() || line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                match name.trim().to_ascii_lowercase().as_str() {
                    "content-length" => {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                    "authorization" => {
                        auth = Some(value.trim().to_string());
                    }
                    _ => {}
                }
            }
        }
        if let Some(a) = auth {
            *last_auth_writer.lock() = Some(a);
        }
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).ok();
        }

        if method != "POST" || path != "/agent/enroll" {
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .ok();
            continue;
        }

        let n = rc.fetch_add(1, Ordering::SeqCst);
        let (status, extra_headers, payload): (&str, &str, String) = match behaviour {
            Behaviour::Success => ("200 OK", "", success_body()),
            Behaviour::Unauthorized => ("401 Unauthorized", "", String::new()),
            Behaviour::Forbidden => ("403 Forbidden", "", String::new()),
            Behaviour::RetryThenSuccess if n == 0 => (
                "503 Service Unavailable",
                "Retry-After: 1\r\n",
                String::new(),
            ),
            Behaviour::RetryThenSuccess => ("200 OK", "", success_body()),
            Behaviour::AlwaysUnavailable => (
                "503 Service Unavailable",
                "Retry-After: 1\r\n",
                String::new(),
            ),
        };

        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        stream.write_all(response.as_bytes()).ok();
        stream.flush().ok();
    });

    Server {
        addr,
        request_count,
        last_authorization: last_auth,
        _join: join,
    }
}

fn creds(addr: &str) -> Credentials {
    Credentials {
        access_token: "tok_xyz".to_string(),
        access_expires_at: Utc::now() + chrono::Duration::hours(1),
        refresh_token: "rt_xyz".to_string(),
        refresh_expires_at: Utc::now() + chrono::Duration::days(30),
        control_plane_url: format!("http://{addr}"),
        user_id: Some("user_test".to_string()),
        allocation_id: Some("alloc_test".to_string()),
        size_bytes: None,
        server_addr: None,
    }
}

#[test]
fn enroll_persists_cert_files_on_200() {
    let srv = start(Behaviour::Success);
    let dir = Tmp::new();
    let enrolled = enroll::enroll(&creds(&srv.addr), &dir.0).expect("enroll ok");

    assert_eq!(enrolled.cert_path, dir.0.join("cert.pem"));
    assert_eq!(enrolled.key_path, dir.0.join("key.pem"));
    assert_eq!(enrolled.ca_path, dir.0.join("ca.pem"));
    assert_eq!(enrolled.server_addr, "tenant-acme.orlop.example.com");
    assert_eq!(enrolled.cert_serial, "0d");
    assert_eq!(enrolled.allocation_id.as_deref(), Some("alloc_test"));
    assert_eq!(enrolled.size_bytes, Some(5 * 1024 * 1024 * 1024));
    assert!(enrolled.cert_path.exists());
    assert!(enrolled.key_path.exists());
    assert!(enrolled.ca_path.exists());

    let auth = srv.last_authorization.lock().clone().unwrap_or_default();
    assert_eq!(auth, "Bearer tok_xyz");
}

#[test]
fn enroll_unauthorized_says_re_enroll() {
    let srv = start(Behaviour::Unauthorized);
    let dir = Tmp::new();
    let err = enroll::enroll(&creds(&srv.addr), &dir.0).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("re-enroll"), "msg: {msg}");
    assert!(!dir.0.join("cert.pem").exists());
}

#[test]
fn enroll_forbidden_reports_access_denied() {
    let srv = start(Behaviour::Forbidden);
    let dir = Tmp::new();
    let err = enroll::enroll(&creds(&srv.addr), &dir.0).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("403"), "msg: {msg}");
    assert!(msg.contains("access denied"), "msg: {msg}");
}

#[test]
fn enroll_503_with_retry_after_retries_once_and_succeeds() {
    let srv = start(Behaviour::RetryThenSuccess);
    let dir = Tmp::new();
    let enrolled = enroll::enroll(&creds(&srv.addr), &dir.0).expect("retry succeeded");
    assert_eq!(enrolled.server_addr, "tenant-acme.orlop.example.com");
    assert_eq!(srv.request_count.load(Ordering::SeqCst), 2);
}

#[test]
fn enroll_503_persistent_fails_after_one_retry() {
    let srv = start(Behaviour::AlwaysUnavailable);
    let dir = Tmp::new();
    let err = enroll::enroll(&creds(&srv.addr), &dir.0).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("503"), "msg: {msg}");
    // One initial + one retry = 2 calls; no third.
    assert_eq!(srv.request_count.load(Ordering::SeqCst), 2);
}

#[test]
fn shred_after_enroll_leaves_no_cert_files() {
    let srv = start(Behaviour::Success);
    let dir = Tmp::new();
    enroll::enroll(&creds(&srv.addr), &dir.0).unwrap();
    enroll::shred(&dir.0).unwrap();
    assert!(!dir.0.join("cert.pem").exists());
    assert!(!dir.0.join("key.pem").exists());
    assert!(!dir.0.join("ca.pem").exists());
}
