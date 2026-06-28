# Quickstart

Bring up the full orlop stack on one host, give an agent a durable disk, then
write a file, restart the stack, and watch it survive — in a few commands.

`orlop dev up` runs the whole single-node stack (control plane + data-plane
server + one mounted disk) with embedded SQLite and no external dependencies.
To run each piece by hand instead — to understand the architecture or to model a
custom deploy — see [`manual-bring-up.md`](manual-bring-up.md).

## Hand it to your coding agent

If a coding agent (Claude Code, Cursor, and the like) has a shell here, paste
this and let it drive:

```text
Set up a single-node orlop stack by following
https://orlop.dev/reference/standalone-quickstart.md. Install with
`curl -fsSL https://orlop.dev/install.sh | sh`, run `orlop doctor`, then bring
the whole stack up with `orlop dev up`. In a second shell, write a file to the
mounted disk, stop the stack (Ctrl-C), bring it back up, and confirm the file
survived. Check first that ports 8080, 7878, and 8443 are free and that FUSE
(Linux) or the built-in NFS client (macOS) is available; stop if anything is
missing.
```

## Prerequisites

- Linux or macOS, with three free ports: `8080` (control plane), `7878` (server
  ops), `8443` (server data).
- Mount support: Linux uses FUSE (`/dev/fuse` and `fuse3`); macOS uses its
  built-in NFS client. `orlop doctor` (step 1) confirms this host can mount.

## 1. Install the binaries

Downloads prebuilt `orlop`, `orlop-control`, and `orlop-server` for your OS and
architecture into `~/.local/bin`:

```bash
curl -fsSL https://orlop.dev/install.sh | sh
orlop doctor
```

Override the target dir with `ORLOP_BIN_DIR`, or pin a release with
`ORLOP_VERSION=v0.2.1`. If the install dir isn't on your `PATH`, the script
prints the line to add. `orlop dev up` finds `orlop-control` and `orlop-server`
next to the `orlop` binary or on your `PATH`.

<details>
<summary>Build from source instead (needs the Go and Rust toolchains)</summary>

From the repo root:

```bash
GOWORK=off go build -o ./bin/orlop-control ./cmd/orlop-control
GOWORK=off go build -o ./bin/orlop-server  ./cmd/orlop-server
cargo build --release --bin orlop          # → target/release/orlop
export PATH="$PWD/bin:$PWD/target/release:$PATH"

orlop doctor
```

</details>

## 2. Bring up the stack

```bash
orlop dev up
```

One command starts the SQLite control plane, registers and starts the
data-plane server, mints an enroll token, and mounts a disk — then supervises
all three. It prints where things are and stays in the foreground:

```text
orlop dev stack is up:
  control plane  http://localhost:8080
  data plane     ops localhost:7878  data localhost:8443
  disk mounted   ./orlop-dev/mnt  (agent demo)

  stop:     Ctrl-C, or `orlop dev down` from another shell
```

All state lives under `./orlop-dev` (override with `--dir`); the disk mounts at
`./orlop-dev/mnt`. From another shell, inspect it any time:

```bash
orlop status        # control plane / data plane / mount + liveness; --json for machine output
```

`status` probes the actual PIDs and mount (it doesn't just trust its cached
state), so a stack that died uncleanly reports `DEAD` — never a false `UP`. The
header is `UP` / `DEGRADED` / `DEAD`; `--json` exposes it as `dev_stack.state`
(`up` / `degraded` / `dead`) for scripts to poll.

### Run it without holding a terminal (CI, agents, IDEs)

`orlop dev up` blocks in the foreground until Ctrl-C. To drive the stack from a
script, CI step, or agent, bring it up detached and stop it by name — no
PID-hunting:

```bash
orlop dev up --detach     # -d: preflights, mounts, then returns 0 once ready
orlop status              # ... do your work against ./orlop-dev/mnt ...
orlop dev down            # graceful teardown; waits for unmount + exit, returns 0
```

`dev down` is idempotent (a no-op if nothing is running) and reconciles a stack
whose supervisor died uncleanly, so it's safe to call from a CI cleanup step.
The detached supervisor logs to `./orlop-dev/dev.log`.

A foreground `dev up` stopped by **Ctrl-C / SIGTERM exits 0** — the intended,
graceful stop — so a process supervisor or CI step won't mistake a normal stop
for a crash. It exits non-zero only on a real failure (the stack couldn't come
up, a component crashed while running, or teardown errored).

## 3. Prove durability

In a second shell, write a file to the disk:

```bash
echo "hello from a durable agent disk" > ./orlop-dev/mnt/hello.txt
mkdir -p ./orlop-dev/mnt/sub && echo "nested" > ./orlop-dev/mnt/sub/note.md
```

Now stop the stack with **Ctrl-C** in the first shell (or `orlop dev down` from
another). The mount point goes empty — the data isn't on your local filesystem,
it's in the data-plane server's store under `./orlop-dev/dg-data`, which teardown
leaves intact. Bring the stack back up against the same directory and the files
return:

```bash
orlop dev up                       # same default --dir ./orlop-dev, reuses the data
# in another shell:
cat ./orlop-dev/mnt/hello.txt      # → hello from a durable agent disk
cat ./orlop-dev/mnt/sub/note.md    # → nested
```

The disk survived a full teardown and restart because it lives in the
data-plane server, not in the mount point.

## Cleanup

Ctrl-C (or `orlop dev down`) stops the stack; to discard the data too, remove
the work directory:

```bash
orlop dev down       # if it's still running detached
rm -rf ./orlop-dev
```

## Going further

- [`manual-bring-up.md`](manual-bring-up.md) — run the control plane, server,
  token, and mount by hand. Start here to understand the pieces, customize ports
  or storage, or adapt the bring-up for your own orchestration.
- [`database-backends.md`](database-backends.md) — Postgres instead of SQLite,
  for multiple control-plane replicas.
- [`control-plane-runbook.md`](control-plane-runbook.md) — production operation,
  quota enforcement, and JuiceFS-backed storage.
