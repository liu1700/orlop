# Quality and robustness

Orlop is infrastructure. A successful unit test is necessary but not enough:
the release path must also exercise protocol compatibility, a real kernel
mount, crash boundaries, migrations, and operational recovery.

## Required gates

| Layer | Gate |
|---|---|
| Go control/data plane | build, vet, and race-enabled tests |
| Rust mount client | build, tests, clippy with warnings denied |
| Wire protocol | Go/Rust message round trips and append-only optional fields |
| POSIX | pjdfstest through Linux FUSE and the real mTLS data plane |
| Packaging | static musl Linux binary; reject a `libfuse.so` dependency |
| Distribution | run the static mount binary on supported Debian bases |
| Operations | bounded-cardinality metrics, health check, stale-mount cleanup |
| Metadata | transactional mutations, CAS, chunk refcount invariants, migration tests |

The pull-request POSIX gate currently runs a regular-file hard-link smoke and
pjdfstest's link error-semantics test because together they cross the inode,
manifest, journal, protocol, FUSE-cache, and chunk-GC boundaries. The full
pjdfstest suite remains available through the same rig; failures and mount
deaths are preserved as artifacts.

## Practices adopted from similar filesystems

- JuiceFS publishes concrete pjdfstest and LTP results instead of relying on a
  generic “POSIX compatible” claim. Orlop follows that model with an explicit
  compatibility matrix and kernel-level tests.
- Mountpoint for Amazon S3 documents unsupported semantics and fails early
  rather than pretending an operation is durable. Orlop uses the same rule:
  capability gaps stay visible in the matrix.
- Mountpoint uses a reference model for filesystem behavior. Orlop should add
  a model-based randomized manifest test next, comparing path/inode/refcount
  state after mixed link, rename, write, and unlink sequences.
- CephFS provides forward/backward scrub and health signals for stuck client
  requests. Orlop's next operational milestone is an online metadata/chunk
  scrub that verifies both directions and exports progress/failure metrics.
- JuiceFS exposes `fsck` and garbage collection as operator commands. Orlop's
  chunk GC already tolerates orphans; it should grow a read-only `fsck` report
  before any repair mode is introduced.

Primary references:

- [JuiceFS POSIX compatibility](https://juicefs.com/docs/community/posix_compatibility)
- [JuiceFS command reference (`fsck`, `gc`, and diagnostics)](https://juicefs.com/docs/community/command_reference/)
- [Mountpoint filesystem semantics](https://github.com/awslabs/mountpoint-s3/blob/main/doc/SEMANTICS.md)
- [CephFS scrub](https://docs.ceph.com/en/latest/cephfs/scrub/)
- [CephFS health messages](https://docs.ceph.com/en/latest/cephfs/health-messages/)
