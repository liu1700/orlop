//! Two-agent lease contention integration test (scoped to in-process checks).
//!
//! Full end-to-end testing (real orlop-server process, two TLS clients, revoke
//! round-trip latency assertion) is deferred. The Go-side tests in
//! cmd/orlop-server/lease_test.go cover the contention state machine
//! (TestGrantAfterMinHoldRevokesAndRegrants, TestRevokeTimeoutForceEvicts,
//! TestManifestPutFromNonHolderTriggersRevoke). Rust-side LeaseManager unit
//! tests in src/lease.rs cover the bookkeeping invariants. This file covers
//! the wire-format round-trip and any in-process checks reachable without a
//! real server.
//!
//! TODO(#79-followup): Add a real two-process test once a TestServer harness
//! is available. Acceptance: revoke RTT < 200 ms over 50 ms-RTT netem.

use orlop::backend::dataplane::messages::{
    LeaseGrantRequest, LeaseGrantResponse, LeaseMode, LeaseRefreshRequest, LeaseRefreshResponse,
    LeaseReleaseRequest, LeaseReleaseResponse, LeaseRevokeRequest,
};

/// Server constructs the revoke push; client decodes it from the push frame.
/// This is the primary cross-boundary wire-format test for Task 13.
#[test]
fn lease_revoke_request_round_trips() {
    let lease_id: Vec<u8> = (0u8..16).collect();
    let server_side = LeaseRevokeRequest {
        lease_id: lease_id.clone(),
        reason: "contention".into(),
    };
    let bytes = rmp_serde::to_vec_named(&server_side).expect("encode");

    // Sanity: msgpack `bin` family (0xc4..=0xc6) must be present for lease_id.
    assert!(bytes.iter().any(|b| (0xc4..=0xc6).contains(b)));

    let client_side: LeaseRevokeRequest = rmp_serde::from_slice(&bytes).expect("decode");
    assert_eq!(client_side.lease_id, lease_id);
    assert_eq!(client_side.reason, "contention");
}

/// Client→server grant request and server→client grant response both survive
/// a full msgpack round-trip.
#[test]
fn lease_grant_round_trips_both_directions() {
    // Client request → server decode.
    let req = LeaseGrantRequest {
        path: "/contended.txt".into(),
        mode: LeaseMode::ExclusiveWrite,
    };
    let bytes = rmp_serde::to_vec_named(&req).expect("encode req");
    let decoded: LeaseGrantRequest = rmp_serde::from_slice(&bytes).expect("decode req");
    assert_eq!(decoded.path, "/contended.txt");
    assert!(matches!(decoded.mode, LeaseMode::ExclusiveWrite));

    // Server response → client decode.
    let resp = LeaseGrantResponse {
        lease_id: vec![42u8; 16],
        expires_at_unix_ms: 1_700_000_000_000,
        mode_granted: LeaseMode::ExclusiveWrite,
    };
    let bytes = rmp_serde::to_vec_named(&resp).expect("encode resp");
    let decoded: LeaseGrantResponse = rmp_serde::from_slice(&bytes).expect("decode resp");
    assert_eq!(decoded.lease_id.len(), 16);
    assert_eq!(decoded.expires_at_unix_ms, 1_700_000_000_000);
    assert!(matches!(decoded.mode_granted, LeaseMode::ExclusiveWrite));
}

#[test]
fn lease_refresh_round_trips() {
    let req = LeaseRefreshRequest {
        lease_id: vec![7u8; 16],
    };
    let b = rmp_serde::to_vec_named(&req).unwrap();
    let r: LeaseRefreshRequest = rmp_serde::from_slice(&b).unwrap();
    assert_eq!(r.lease_id.len(), 16);

    let resp = LeaseRefreshResponse {
        expires_at_unix_ms: 1234,
    };
    let b = rmp_serde::to_vec_named(&resp).unwrap();
    let r: LeaseRefreshResponse = rmp_serde::from_slice(&b).unwrap();
    assert_eq!(r.expires_at_unix_ms, 1234);
}

#[test]
fn lease_release_round_trips() {
    let req = LeaseReleaseRequest {
        lease_id: vec![1u8; 16],
        dirty_flushed: true,
    };
    let b = rmp_serde::to_vec_named(&req).unwrap();
    let r: LeaseReleaseRequest = rmp_serde::from_slice(&b).unwrap();
    assert!(r.dirty_flushed);
    assert_eq!(r.lease_id, vec![1u8; 16]);

    let resp = LeaseReleaseResponse {};
    let b = rmp_serde::to_vec_named(&resp).unwrap();
    let _r: LeaseReleaseResponse = rmp_serde::from_slice(&b).unwrap();
}

/// SharedRead mode encodes and decodes without confusion with ExclusiveWrite.
#[test]
fn lease_mode_discriminants_survive_round_trip() {
    for mode in [LeaseMode::SharedRead, LeaseMode::ExclusiveWrite] {
        let req = LeaseGrantRequest {
            path: "/f".into(),
            mode,
        };
        let b = rmp_serde::to_vec_named(&req).unwrap();
        let got: LeaseGrantRequest = rmp_serde::from_slice(&b).unwrap();
        assert_eq!(got.mode, mode);
    }
}
