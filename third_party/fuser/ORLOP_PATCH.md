# Orlop session handoff patch

This directory vendors `fuser` 0.15.1 (MIT, see `LICENSE.md`) so Orlop can expose
a fail-safe live-upgrade boundary without relying on private struct layout.

The Orlop-specific implementation is intentionally limited to
`src/session.rs`, plus the `SessionGate` re-export in `src/lib.rs`:

- `SessionGate` parks the single request-dispatch loop between requests. A
  process-directed signal interrupts a blocking `/dev/fuse` read so a handoff
  does not depend on new filesystem traffic.
- `Session::run_with_gate` uses that gate while preserving the ordinary
  `Session::run` behavior.
- `Session::from_initialized_fd` wraps an fd whose FUSE INIT handshake was
  completed by the predecessor and restores the negotiated protocol version.

The handoff integration tests exercise pause/resume, timeout rollback, and the
versioned transfer protocol. Keep this patch small when updating fuser and
prefer an upstream API once one provides the same initialized-session contract.
