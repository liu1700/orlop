# Quickstart

Stand up the full orlop stack on one host and give an agent a durable disk in
**two commands** — install, then `orlop dev up`. That second command runs the
whole single-node stack: control plane + data-plane server + one mounted disk.

## 1. Install the binaries

Installs into `~/.local/bin`:

```bash
curl -fsSL https://orlop.dev/install.sh | sh
```

## 2. Bring up the stack

```bash
orlop dev up
```

It prints where each component lives and stays in the foreground:

```text
  disk mounted   ./orlop-dev/mnt  (agent demo)

  stop:     Ctrl-C, or `orlop dev down` from another shell
```

## 3. See it persist (optional)

Write a file to the disk:

```bash
echo "hello from a durable agent disk" > ./orlop-dev/mnt/hello.txt
```

Stop the stack — Ctrl-C in the first shell, or `orlop dev down` from another.
The mount point goes empty; the data isn't on your local filesystem. Bring it
back up and read the file back:

```bash
orlop dev up                     # same default --dir ./orlop-dev, reuses the data
cat ./orlop-dev/mnt/hello.txt    # → hello from a durable agent disk
```

## Clean up

Ctrl-C (or `orlop dev down`) stops the stack. To discard the data too, remove
the work directory:

```bash
rm -rf ./orlop-dev
```

## Going further

For install options, building from source, overriding ports and paths,
inspecting the stack, running it detached (CI/agents/IDEs), and troubleshooting,
see [`advanced-usage.md`](advanced-usage.md). To run each component by hand, see
[`manual-bring-up.md`](manual-bring-up.md).
