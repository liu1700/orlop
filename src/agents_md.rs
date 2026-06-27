//! Inject a marker-bracketed Orlop stanza into the cwd's `AGENTS.md` so
//! agents that read AGENTS.md (Cursor, Aider, Codex CLI, …) but don't speak
//! the SKILL.md protocol still learn that `/mnt/orlop` is available.
//!
//! Idempotent: re-running over an existing block replaces it in place. We
//! never touch a file outside the current working directory and never create
//! `AGENTS.md` unless cwd looks like a project root.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const BEGIN_MARKER: &str = "<!-- orlop:begin -->";
const END_MARKER: &str = "<!-- orlop:end -->";
const PROJECT_MARKERS: &[&str] = &[
    ".git",
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
];

#[derive(Debug, PartialEq, Eq)]
pub enum InjectAction {
    Created,
    Appended,
    Updated,
    Unchanged,
    SkippedNoFile,
}

pub fn render_stanza(mountpoint: &Path) -> String {
    let mp = mountpoint.display();
    format!(
        "{begin}\n## Orlop — cross-agent persistent disk\n\n\
Orlop is mounted at `{mp}`. Treat it as an ordinary directory and operate\n\
with normal filesystem tools (ls, cat, rg, edit, python). Files persist\n\
across sessions, machines, and agent runtimes.\n\n\
Prefer `{mp}` over `/tmp` or `~/` for any output worth keeping — notes,\n\
memories, drafts, datasets, or artifacts another agent or teammate will\n\
read later. Skip for scratch work or files inside this repo.\n\n\
If an orlop command fails with an authentication error, ask the host to\n\
re-enroll this agent (mint a fresh enroll token and re-run\n\
`orlop mount --from-env`).\n\
{end}\n",
        begin = BEGIN_MARKER,
        end = END_MARKER,
        mp = mp,
    )
}

pub fn cwd_looks_like_project(cwd: &Path) -> bool {
    PROJECT_MARKERS.iter().any(|m| cwd.join(m).exists())
}

/// Top-level entry called from `orlop mount`. Returns the AGENTS.md path that
/// was touched (if any) plus what happened — caller logs a one-line notice.
pub fn maybe_inject_into_cwd(mountpoint: &Path) -> Result<(Option<PathBuf>, InjectAction)> {
    let cwd = std::env::current_dir().context("get cwd")?;
    maybe_inject_into_cwd_at(mountpoint, &cwd)
}

/// Like `maybe_inject_into_cwd` but takes an explicit working directory.
/// Used by the daemon grandchild, which has been chdir'd to `/` by daemonize;
/// pass the parent's cwd captured before `daemonize::execute()`.
pub fn maybe_inject_into_cwd_at(
    mountpoint: &Path,
    cwd: &Path,
) -> Result<(Option<PathBuf>, InjectAction)> {
    let path = cwd.join("AGENTS.md");
    let stanza = render_stanza(mountpoint);

    if path.exists() {
        let action = inject(&path, &stanza)?;
        return Ok((Some(path), action));
    }
    if cwd_looks_like_project(cwd) {
        let action = inject(&path, &stanza)?;
        return Ok((Some(path), action));
    }
    Ok((None, InjectAction::SkippedNoFile))
}

pub fn inject(path: &Path, stanza: &str) -> Result<InjectAction> {
    let body = match fs::read_to_string(path) {
        Ok(b) => b,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };

    if let (Some(start), Some(end)) = (body.find(BEGIN_MARKER), body.find(END_MARKER)) {
        if start < end {
            let before = &body[..start];
            let after = &body[end + END_MARKER.len()..];
            let trimmed_after = after.strip_prefix('\n').unwrap_or(after);
            let new_body = format!("{}{}{}", before, stanza, trimmed_after);
            if new_body == body {
                return Ok(InjectAction::Unchanged);
            }
            fs::write(path, new_body).with_context(|| format!("write {}", path.display()))?;
            return Ok(InjectAction::Updated);
        }
    }

    let separator = if body.is_empty() || body.ends_with("\n\n") {
        ""
    } else if body.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    let new_body = format!("{}{}{}", body, separator, stanza);
    fs::write(path, &new_body).with_context(|| format!("write {}", path.display()))?;
    Ok(if body.is_empty() {
        InjectAction::Created
    } else {
        InjectAction::Appended
    })
}

/// Remove the Orlop block from the cwd's AGENTS.md, leaving everything else
/// intact. Used by `orlop unmount` / future cleanup paths.
pub fn remove_from_cwd() -> Result<RemoveAction> {
    let cwd = std::env::current_dir().context("get cwd")?;
    let path = cwd.join("AGENTS.md");
    if !path.exists() {
        return Ok(RemoveAction::Missing);
    }
    let body = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let (Some(start), Some(end)) = (body.find(BEGIN_MARKER), body.find(END_MARKER)) else {
        return Ok(RemoveAction::NotInjected);
    };
    if start >= end {
        return Ok(RemoveAction::NotInjected);
    }
    let before = body[..start].trim_end_matches('\n');
    let after = body[end + END_MARKER.len()..].trim_start_matches('\n');
    let new_body = match (before.is_empty(), after.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!("{}\n", before),
        (true, false) => format!("{}\n", after),
        (false, false) => format!("{}\n\n{}\n", before, after),
    };
    if new_body.is_empty() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        Ok(RemoveAction::FileRemoved)
    } else {
        fs::write(&path, new_body).with_context(|| format!("write {}", path.display()))?;
        Ok(RemoveAction::Removed)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RemoveAction {
    Removed,
    FileRemoved,
    NotInjected,
    Missing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn stanza() -> String {
        render_stanza(&PathBuf::from("/mnt/orlop"))
    }

    #[test]
    fn create_into_empty_file_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        let action = inject(&path, &stanza()).unwrap();
        assert_eq!(action, InjectAction::Created);
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains(BEGIN_MARKER));
        assert!(body.contains(END_MARKER));
        assert!(body.contains("/mnt/orlop"));
    }

    #[test]
    fn append_to_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        fs::write(&path, "# project rules\n\nbe careful with prod.\n").unwrap();
        let action = inject(&path, &stanza()).unwrap();
        assert_eq!(action, InjectAction::Appended);
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("# project rules"));
        assert!(body.contains(BEGIN_MARKER));
    }

    #[test]
    fn update_in_place_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        fs::write(&path, "# top\n\n").unwrap();
        inject(&path, &stanza()).unwrap();
        let after_first = fs::read_to_string(&path).unwrap();

        let action = inject(&path, &stanza()).unwrap();
        assert_eq!(action, InjectAction::Unchanged);
        let after_second = fs::read_to_string(&path).unwrap();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn updates_when_mountpoint_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        inject(&path, &render_stanza(&PathBuf::from("/mnt/orlop"))).unwrap();
        let action = inject(&path, &render_stanza(&PathBuf::from("/work/orlop"))).unwrap();
        assert_eq!(action, InjectAction::Updated);
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("/work/orlop"));
        assert!(!body.contains("/mnt/orlop"));
    }

    #[test]
    fn remove_block_preserves_surroundings() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        fs::write(&path, "# rules\n\nA\n").unwrap();
        inject(&path, &stanza()).unwrap();
        // emulate user-edited tail content after the block
        let mut body = fs::read_to_string(&path).unwrap();
        body.push_str("\n## later section\n\nB\n");
        fs::write(&path, &body).unwrap();

        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let action = remove_from_cwd().unwrap();
        std::env::set_current_dir(cwd).unwrap();

        assert_eq!(action, RemoveAction::Removed);
        let after = fs::read_to_string(&path).unwrap();
        assert!(after.contains("# rules"));
        assert!(after.contains("## later section"));
        assert!(!after.contains(BEGIN_MARKER));
    }
}
