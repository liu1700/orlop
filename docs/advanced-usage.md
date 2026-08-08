# Advanced usage

Companion to the [quickstart](standalone-quickstart.md). The quickstart gets a
single-node stack up in two commands and proves the disk persists; this page
covers everything past that minimal path — install options, building from
source, what `orlop dev up` actually does, overriding ports and paths,
inspecting the stack, running it detached for CI/agents/IDEs, where the data
lives, and troubleshooting.

To run each component by hand instead of through `orlop dev up`, see
[`manual-bring-up.md`](manual-bring-up.md).

## Hand it to your coding agent

If a coding agent (Claude Code, Cursor, and the like) has a shell here, paste
this and let it drive:

```text
Set up a single-node orlop stack by following
https://orlop.dev/reference/standalone-quickstart.md, but bring the stack up
with `orlop dev up --detach` so it returns once the disk is mounted instead of
holding the terminal. Then run the quickstart's persistence check. If
`orlop dev up` reports a preflight failure, fix what it names and retry.
```

## Install options

The installer drops three binaries — `orlop`, `orlop-control`, and
`orlop-server` — into `~/.local/bin`. `orlop dev up` finds `orlop-control` and
`orlop-server` next to the `orlop` binary or on your `PATH`.

- Override the target dir with `ORLOP_BIN_DIR`.
- Pin a release with `ORLOP_VERSION=v0.6.1`.
- If the install dir isn't on your `PATH`, the script prints the line to add.

### Build from source

Needs the Go and Rust toolchains. From the repo root:

```bash
GOWORK=off go build -o ./bin/orlop-control ./cmd/orlop-control
GOWORK=off go build -o ./bin/orlop-server  ./cmd/orlop-server
cargo build --release --bin orlop          # → target/release/orlop
export PATH="$PWD/bin:$PWD/target/release:$PATH"
```

## What `orlop dev up` does

It runs on embedded SQLite with no external dependencies. One command preflights
the host, then starts the SQLite control plane, registers and starts the
data-plane server, mints an enroll token, and mounts a disk — then supervises
all three. Because it preflights and fails fast with an actionable fix when
something's missing, there's no separate setup step.

### Preflight checks

The preflight checks the three ports (`8080` control plane, `7878` server ops,
`8443` server data), host mount support (Linux FUSE / macOS built-in NFS), and a
writable chunk cache. On a conflict it stops before starting anything, e.g.:

```text
port 8080 (control plane) is already in use; free port 8080, or pass a different --*-port
```

## Override the defaults

Use these when the defaults clash or you want a different layout:

| Flag | Default | Purpose |
|------|---------|---------|
| `--dir <path>` | `./orlop-dev` | work dir for all stack state (db, data, logs) |
| `--mountpoint <path>` | `<dir>/mnt` | where the disk is mounted |
| `--control-port <port>` | `8080` | control-plane port |
| `--ops-port <port>` | `7878` | data-plane ops port |
| `--data-port <port>` | `8443` | data-plane data port |

## Inspect the stack

From another shell, inspect it any time:

```bash
orlop status        # control plane / data plane / mount + liveness; --json for machine output
```

`status` probes the actual PIDs and mount (it doesn't just trust its cached
state), so a stack that died uncleanly reports `DEAD` — never a false `UP`. The
header is `UP` / `DEGRADED` / `DEAD`; `--json` exposes it as `dev_stack.state`
(`up` / `degraded` / `dead`) for scripts to poll.

## Run it without holding a terminal (CI, agents, IDEs)

`orlop dev up` blocks in the foreground until Ctrl-C. To drive the stack from a
script, CI step, or agent, bring it up detached and stop it by name — no
PID-hunting:

```bash
orlop dev up --detach     # -d: preflights, mounts, then returns 0 once ready
orlop status              # ... do your work against ./orlop-dev/mnt ...
orlop dev down            # graceful teardown; waits for unmount + exit, returns 0
```

`dev down` is idempotent (a no-op if nothing is running) and reconciles a stack
whose supervisor died uncleanly, so it's safe to call from a CI cleanup step —
and to clean up a detached stack before `rm -rf ./orlop-dev`. The detached
supervisor logs to `./orlop-dev/dev.log`.

A foreground `dev up` stopped by **Ctrl-C / SIGTERM exits 0** — the intended,
graceful stop — so a process supervisor or CI step won't mistake a normal stop
for a crash. It exits non-zero only on a real failure (the stack couldn't come
up, a component crashed while running, or teardown errored).

## Where the data lives

The persistence demo in the [quickstart](standalone-quickstart.md#3-see-it-persist-optional)
works because the data isn't in the mount point — it's in the data-plane
server's store under `./orlop-dev/orlop-data`, which teardown leaves intact. Bring
the stack back up against the same `--dir` and the files return. The disk
survives a full teardown and restart because it lives in the data-plane server,
not in the mount point.

## Troubleshooting

`orlop dev up` preflights for you, but you can run the same host checks on their
own at any time:

```bash
orlop doctor --dev   # ports free + mount support + writable cache, exits non-zero if not
```

Plain `orlop doctor` (no `--dev`) additionally looks for a config + credentials;
those are only for a config-based `orlop mount` — `orlop dev up` supplies them
itself, so ignore those notes here.

### Find and reclaim stale Linux FUSE mounts

If a mount client's supervisor dies, the kernel mount may remain while the
userspace FUSE server is gone. Such a path returns `ENOTCONN` ("Transport
endpoint is not connected"). Enumerate from the mount table rather than with a
filesystem glob, because a glob can silently skip the disconnected path:

```bash
orlop mount ls
orlop mount ls --json
orlop mount check /mnt/orlop  # exits non-zero unless this exact mount is alive
```

Each path probe has a two-second deadline. A wedged but still-connected FUSE
daemon is reported as `inaccessible` after the deadline and is never treated as
safe to detach.

Cleanup is idempotent, including when two janitors race, and only lazy-detaches
Orlop-only mount stacks that currently return `ENOTCONN`; it stops if a live
layer is exposed and skips a path entirely if another filesystem is stacked
there:

```bash
orlop unmount --stale
```

The command acts in its current Linux mount namespace. From a Kubernetes node
debug container, enter the host mount namespace first (for example with
`nsenter -t 1 -m`) rather than relying on a `chroot` or bind-mounted copy of the
host filesystem.

### Adopt or replace a live Linux mount client

`adopt` is for a mount whose userspace FUSE process is still alive. Without a
replacement binary, it authenticates against that process, verifies the exact
mountpoint, and atomically refreshes Orlop's local PID record:

```bash
orlop mount --adopt /mnt/orlop
```

For an in-place binary upgrade, pass an absolute executable path:

```bash
orlop mount --adopt /mnt/orlop \
  --replace-with /opt/orlop/releases/0.4.0/orlop
```

The old process remains authoritative until the new process has received the
live `/dev/fuse` descriptor, validated the versioned state snapshot, rebuilt
its backends, and reacquired required leases. Dirty open files are flushed
before transfer. Any preparation failure resumes the old request loop; success
returns the successor PID and leaves the mount ID and kernel connection intact.

The handoff socket is owner-only and peers are checked with `SO_PEERCRED`.
Same-user callers (or root) must run in the same mount namespace, and the new
binary, configuration, certificates, and backend endpoints must remain
available there. This cannot revive `ENOTCONN`: after the last `/dev/fuse` fd
holder dies, use stale cleanup and create a new mount.

## Going further

- [`manual-bring-up.md`](manual-bring-up.md) — run the control plane, server,
  token, and mount by hand. Start here to understand the pieces, customize ports
  or storage, or adapt the bring-up for your own orchestration.
- [`database-backends.md`](database-backends.md) — Postgres instead of SQLite,
  for multiple control-plane replicas.
- [`control-plane-runbook.md`](control-plane-runbook.md) — production operation,
  quota enforcement, and JuiceFS-backed storage.
