//! Orlop data plane — long-lived binary-framed mTLS connection.
//!
//! Companion server: `cmd/orlop-server/dataplane/`. Frame layout, op codes,
//! and msgpack message shapes are mirrored on both sides; keep them in sync.
//!
//! See `docs/design-data-plane.md` Layer 2 for first-principles reasoning
//! and `docs/design-data-plane.md` for the wire format reference.

pub mod cache;
pub mod client;
pub mod codec;
pub mod messages;
pub mod protocol;
pub mod store;

pub use cache::{CacheStats, ChunkCache};
pub use client::{DataClient, DataClientConfig, TransportMode};
pub use store::DataStore;
