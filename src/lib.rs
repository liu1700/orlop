pub mod agents_md;
pub mod audit;
pub mod backend;
pub mod config;
pub mod daemon;
pub mod dev;
pub mod doctor;
pub mod enroll;
// FUSE-only — the macOS mount path goes through `nfs.rs` instead, so darwin
// builds (now cross-compiled from Linux via cargo-zigbuild) don't need the
// `fuser` crate or its pkg-config / libfuse3 / macFUSE dependencies. Shared
// chunk-writing utilities used by both paths (`write_handle`) live at the
// crate root, not under `fs::`, so they stay available on every platform.
#[cfg(target_os = "linux")]
pub mod fs;
pub mod lease;
pub mod login;
pub mod mount;
pub mod nfs;
pub mod policy;
pub mod store;
pub mod util;
pub mod write_handle;
