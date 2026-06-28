# Agent memory on a durable, per-agent filesystem

Give your AI agent durable, isolated memory: a per-agent POSIX filesystem it
mounts and reads like a local disk — the same idea as JuiceFS, but scoped to one
agent and safe to share across many. The bytes live in a remote
content-addressed store, so the memory outlives the sandbox and re-attaches,
unchanged, on the agent's next run or a different machine.

"Memory" here is whatever the agent carries across runs: a running notes file,
tool outputs, downloaded datasets, and the raw transcripts a higher-level memory
layer later indexes or summarizes. Orlop does not extract, embed, or rank any of
it — it is the durable disk underneath, which the agent (or a memory layer above
it) reads and writes with ordinary file operations. This guide shows how to wire
an agent up to its own orlop disk — the pattern an agent platform follows,
abstracted to the parts you need.

## Before you start

- An agent that runs in a sandbox — a container, microVM, or local shell — and
  can read and write files.
- An orlop stack to allocate disks against. On a laptop that's two commands —
  install, then `orlop dev up` ([Quickstart](standalone-quickstart.md)); for a
  fleet, a deployed control plane and data plane
  ([control-plane runbook](control-plane-runbook.md)).
- The `orlop` mount client on the sandbox image — `curl -fsSL
  https://orlop.dev/install.sh | sh`, or copy the static binary in.
- To drive the control plane for steps 1–2: the Go SDK
  (`github.com/liu1700/orlop/client`) for a platform, or the `orlop-control` CLI
  for one-off use.

## Try the round-trip locally first

Before wiring it into an agent, see the whole loop on one host. `orlop dev up`
brings up the stack and mounts a disk at `./orlop-dev/mnt`:

```bash
orlop dev up -d                                    # control plane + data plane + a mounted disk
echo "the build uses Go 1.24" > ./orlop-dev/mnt/MEMORY.md
orlop dev down && orlop dev up -d                  # tear the "sandbox" down and back up
cat ./orlop-dev/mnt/MEMORY.md                      # → the note survived
```

The mount point goes empty on teardown — the bytes were never on local disk —
and the file returns on the next mount. That round-trip — write, lose the
sandbox, get the bytes back — is what the rest of this guide makes *per-agent*.

## Give an agent its own memory in five steps

Steps 1–2 run **host-side** (trusted), against the control plane. Steps 3–5 run
**inside the sandbox**, where the agent is treated as untrusted.

### 1. Allocate a disk for the agent identity

Once per agent, the host — never the agent — asks the control plane to allocate
a durable disk bound to a stable agent identity and an owner, with a byte grant:

```go
// host-side, via the Go SDK (github.com/liu1700/orlop/client)
cp := client.New("https://control.example.com", controlToken)
disk, _ := cp.AllocateDisk(ctx, agentID, ownerID, grantBytes) // durable, bound to this agent
```

The agent never names its own tenant; the host does, out of band. That is what
makes the disk *this agent's* and no one else's. (For scripts, the CLI
`orlop-control token issue --agent <id> --size <bytes>` allocates a disk and
mints the step-2 token in one shot.)

### 2. Mint an enroll token and pass it to the sandbox

At launch, mint a short-lived, agent-scoped enroll token:

```go
token, _ := cp.MintEnrollToken(ctx, agentID)   // single-use; spent on first mount
```

Then inject it into the sandbox environment with the mount coordinates:

```bash
ORLOP_AGENT_ID=<agentID>
ORLOP_CONTROL_PLANE=https://control.example.com
ORLOP_MOUNT_POINT=/mnt/agent-memory     # where the agent sees its disk (required for --from-env)
ORLOP_ENROLL_TOKEN=<token from above>
```

The token is consumed the instant it is redeemed for a certificate, so a leaked
token is useless after the first mount.

### 3. Mount the disk inside the sandbox

Inside the sandbox, one command turns those env vars into a mounted disk:

```bash
orlop mount --from-env
```

`mount` trades the enroll token for a short-lived **mTLS client certificate**
whose identity — a SPIFFE SAN for the agent — is the only thing that authorizes
access, then presents the disk as one plain directory (FUSE on Linux, a
localhost NFS server on macOS). The agent now has a normal read/write disk and
**holds no storage credential it could exfiltrate**; the server confines the
connection to that agent's own path prefix, so it cannot read or widen into
another agent's bytes.

### 4. Read and write memory as plain files

The mount root is just a POSIX directory, so pick a convention and use ordinary
tools (`ls`, `cat`, `rg`, an editor):

```
/mnt/agent-memory/
  MEMORY.md            # the agent reads this first, every run
  notes/               # durable notes it appends to over time
  artifacts/           # tool outputs, datasets, build caches
  transcripts/         # raw logs a memory layer can index later
```

Orlop imposes no layout — it stores raw bytes verbatim, dedupes them by content
hash, and on a write ships only the chunks that changed, so keeping the full raw
trace is cheap. Each path is versioned and overwritten in place by
compare-and-swap, so the agent can *replace* a stale fact rather than append a
correction and hope retrieval picks the latest. On mount, orlop also drops a
short stanza into the working directory's `AGENTS.md` so a file-reading agent
(Claude Code, Cursor) discovers its memory directory on its own — disable with
`--no-inject`.

### 5. Reattach the same disk next session

Before teardown the agent leaves a note for next time; then unmount — the bytes
stay on the data plane with nothing kept warm:

```bash
echo "the build uses Go 1.24" >> "$ORLOP_MOUNT_POINT/MEMORY.md"
orlop unmount "$ORLOP_MOUNT_POINT"
```

The next session repeats steps 2–3 for the **same agent identity**, the same
disk re-mounts — on a different sandbox or a different machine, because the disk
follows the identity, not the host — and the note is there:

```bash
orlop mount --from-env
cat "$ORLOP_MOUNT_POINT/MEMORY.md"      # → the build uses Go 1.24
```

A persistent local chunk cache serves already-seen chunks from local disk, so
the second mount skips re-fetching unchanged data. The whole per-agent loop is:
allocate once, then enroll → mount → use → unmount each session, with the agent
seeing nothing but a directory whose contents persist across runs.

## Where orlop stops

Orlop is the storage plane, not the memory system. It does **not** extract
memory units from transcripts, embed or rank them, build graph or tree
topologies, or consolidate, summarize, and resolve conflicts. Those are the
cognitive jobs of a memory layer above — [Mem0](https://github.com/mem0ai/mem0),
[Letta](https://github.com/letta-ai/letta) (MemGPT),
[Zep / Graphiti](https://github.com/getzep/graphiti),
[Cognee](https://github.com/topoteretes/cognee),
[LangMem](https://github.com/langchain-ai/langmem), and the like. Orlop is the
durable, isolated disk those layers persist their vectors, graph data, key-value
state, transcripts, and cached indexes on; the split is clean — the memory layer
does the cognition, orlop stores the bytes.

The same boundary is why orlop pairs with an agent's built-in file memory, such
as [Claude's filesystem memory tool](https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/memory-tool):
point its memory directory at an orlop mount and the agent's reads and writes
land on a durable, per-agent disk instead of an ephemeral one. Agent sandboxes
like E2B assume such a disk exists; orlop is the zero-trust substrate that
provides one.

## How orlop compares

Orlop is a POSIX-over-object-storage filesystem, so it sits in the same family
as several well-known projects — but, unlike them, it is built specifically for
*per-agent, multi-tenant* use:

| Category | Examples | Isolation model |
| --- | --- | --- |
| Cluster filesystems | JuiceFS, CubeFS, SeaweedFS, CephFS, MooseFS, Alluxio | One trust domain; tenancy is operator-managed (volumes, namespaces, IAM) |
| Object-store FUSE mounts | s3fs-fuse, gcsfuse, Mountpoint for Amazon S3, rclone, goofys | Single user, one shared credential; often partial POSIX (no rename / in-place writes) |
| Per-agent file planes | **orlop** | Each agent gets its own mTLS identity; the server confines it to its own path prefix |

The difference orlop adds is **identity per agent**: each agent gets its own
short-lived certificate, the server isolates it to its own path prefix, and a
compromised agent holds no key that reaches the store or another tenant's bytes.
A general-purpose filesystem hands one shared credential to everything that
mounts it.

These are not mutually exclusive. Orlop's bulk chunk store can live on networked
storage, so you can **run orlop on top of one of them** — back it with JuiceFS,
for instance — and keep per-agent isolation at the layer the agent touches while
a general-purpose system holds the bytes. See the
[control-plane runbook](control-plane-runbook.md) for storage backends.

## Next steps

- [Quickstart](standalone-quickstart.md) — bring up the whole stack on one host
  in two commands.
- [Design overview](design.md) — how the control plane, data plane, and mount
  client fit together.
- [Control-plane runbook](control-plane-runbook.md) — production operation,
  quotas, and storage backends.
