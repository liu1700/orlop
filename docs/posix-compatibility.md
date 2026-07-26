# POSIX compatibility

Orlop implements filesystem semantics explicitly; it does not silently accept
operations that cannot be persisted. Linux FUSE is the production POSIX
surface. macOS uses the in-process `nfsserve` NFSv3 adapter and has a smaller
operation surface.

| Operation | Linux FUSE | macOS NFSv3 | Notes |
|---|---:|---:|---|
| create, read, write, truncate | yes | yes | writes use manifest CAS |
| atomic rename | yes | yes | metadata transaction |
| symlink / readlink | yes | no | the current NFS adapter returns `NFS3ERR_NOTSUPP` |
| hard link | yes | no | the current `nfsserve` VFS trait has no LINK hook |
| chmod | yes | yes | stored metadata; optional kernel permission enforcement |
| chown, atime | yes | no | Linux FUSE only |
| FIFO / socket / device node metadata | yes | no | Linux FUSE only |

## Hard-link guarantees

Every regular file has a stable server-side `inode_id`. All directory entries
for that inode share content, mode, ownership, timestamps, and manifest
version.

- `link(2)` adds a directory entry without incrementing chunk ownership.
- A write through any name updates all names in one SQLite transaction.
- Removing a non-final name preserves the chunks; removing the final name
  decrements their references.
- `rename(a, b)` is a no-op when `a` and `b` already name the same inode.
- Session revert restores a deleted hard-link name onto a surviving inode,
  rather than creating a duplicate inode.

Linux CI runs a regular-file hard-link smoke plus pjdfstest's link error
semantics against a real FUSE mount and the complete mTLS data plane. The full
suite (which also checks special-node hard links that Orlop does not claim)
can be run locally:

```bash
PJDFS_STRICT=1 scripts/pjdfstest-docker.sh
```

The compatibility table is the contract. New POSIX claims require an
end-to-end conformance test, not only an in-memory unit test.
