# Orlop as the Substrate for Agent Memory

An agent's "memory" is everything it needs to carry across turns, sessions, and
machines: scratch files, tool outputs, downloaded datasets, model weights,
intermediate artifacts, and the raw transcripts a higher-level memory layer
later reads, indexes, or summarizes. Orlop is not that higher-level layer: it
is the **durable, isolated, content-addressed storage plane those layers stand
on.** This doc explains what orlop gives an agent-memory stack, and where its
job stops.

## The gap orlop fills

Most agent-memory work focuses on the cognitive parts: what to extract, how to
retrieve, how to consolidate. All of it implicitly assumes a place to *put* the
bytes that is durable, cheap to update, safe under multi-tenancy, and the same
across runs. That substrate is usually an afterthought: a local tmp dir that
dies with the sandbox, an S3 bucket whose credentials the agent can exfiltrate,
or an append-only log that never lets a stale fact be overwritten.

Orlop makes the substrate a first-class, well-behaved primitive. An agent sees
one plain directory at `/mnt/orlop`; everything below is handled for it.

## What orlop brings to a memory layer

**Persistence with zero idle cost.** The bytes live remotely in a
content-addressed chunk store, not in the sandbox. When the sandbox dies the
memory survives, and the next run for the same agent re-mounts the *same* disk
with no compute kept warm in between. Memory that outlives the process is the
baseline requirement for any cross-session agent, and orlop delivers it without
the agent managing a database or a bucket.

**Fidelity-first, cheap to keep raw.** Orlop stores raw bytes verbatim and
dedupes them by BLAKE3 content hash. Keeping the full, uncompressed trace (the
thing a memory layer wants to filter and index *at read time* rather than
discard at write time) is nearly free: identical `node_modules`, datasets, or
repeated tool outputs across sessions collapse to a single stored copy. The
substrate never forces lossy summarization on you to save space.

**Cheap incremental updates.** Content-defined chunking (FastCDC) means a
single-byte edit to a large memory file ships one ~4 MiB chunk, not the whole
file. Local maintenance (touching the part of memory that changed) costs in
proportion to the change, not the total size. A persistent client chunk cache
makes second access run at local-disk speed across mount cycles.

**Overwritable state, not append-only.** Each path's manifest is versioned and
updated by compare-and-swap on that version. A memory layer can atomically
*replace* a fact in place (bind a corrected value to the same path) instead of
appending a new record and hoping retrieval picks the latest. The mechanism for
"this fact changed, the old one is gone" exists at the storage layer, so the
upper layer doesn't have to emulate it on top of an immutable log.

**Per-agent isolation with no shared key.** Each agent gets a short-lived mTLS
client certificate whose identity is the only thing that authorizes access, and
the server confines every connection to that agent's own path prefix. One
agent's memory cannot be read, widened into, or exfiltrated by another, and a
compromised agent holds no credential that reaches the store directly. This is
what makes a *shared* memory plane safe to run across many untrusted agents.

**Auditability.** Every filesystem operation is recorded as an append-only JSONL
audit event (`event`, `path`, `agent_pid`, `allowed`, plus `size` on read/write
ops). What an agent read from or wrote to
its memory is reconstructable after the fact, which is necessary for debugging,
compliance, and trust.

**Portability across machines.** The disk follows the agent identity, not the
host. The same memory mounts on a different machine, a different sandbox, or a
later run, addressed only by the mount root; no storage layout leaks to the
agent.

## Where orlop stops (the boundary)

Orlop is deliberately the storage plane, not the memory system. It does **not**:

- extract memory units from conversations or tool logs,
- embed, rank, or semantically retrieve,
- build graph/tree topologies or do temporal reasoning,
- consolidate, summarize, or resolve conflicts semantically.

Those are the cognitive jobs of the layer above. Orlop's contract is narrow and
strong: give that layer a durable, isolated, versioned, dedup'd POSIX disk, and
get out of its way. The mount root is the path; the agent and its memory layer
navigate it with ordinary filesystem tools.
