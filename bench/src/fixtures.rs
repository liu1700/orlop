use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub const STAT_STORM_FILES: usize = 1000;
pub const LS_LARGE_DIR_FILES: usize = 10_000;
pub const SEQ_FILE_BYTES: u64 = 100 * 1024 * 1024;

pub struct Fixtures {
    root: PathBuf,
}

impl Fixtures {
    pub fn new(mount: &Path) -> Self {
        Self {
            root: mount.join("_bench"),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stat_storm_dir(&self) -> PathBuf {
        self.root.join("stat-storm")
    }

    pub fn ls_large_dir(&self) -> PathBuf {
        self.root.join("ls-large")
    }

    pub fn seq_file(&self) -> PathBuf {
        self.root.join("seq.bin")
    }

    pub fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(&self.root).with_context(|| format!("create {}", self.root.display()))
    }

    pub fn ensure_stat_storm(&self) -> Result<()> {
        let dir = self.stat_storm_dir();
        ensure_file_dir(&dir, STAT_STORM_FILES, b"")
    }

    pub fn ensure_ls_large(&self) -> Result<()> {
        let dir = self.ls_large_dir();
        ensure_file_dir(&dir, LS_LARGE_DIR_FILES, b"")
    }

    pub fn ensure_seq_file(&self) -> Result<()> {
        let path = self.seq_file();
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() == SEQ_FILE_BYTES {
                return Ok(());
            }
        }
        fs::create_dir_all(&self.root)
            .with_context(|| format!("create {}", self.root.display()))?;
        let mut f = File::create(&path).with_context(|| format!("create {}", path.display()))?;
        let chunk = vec![0xA5u8; 1 << 20]; // 1 MiB pattern
        let total_chunks = SEQ_FILE_BYTES / chunk.len() as u64;
        for _ in 0..total_chunks {
            f.write_all(&chunk)?;
        }
        f.sync_all()?;
        Ok(())
    }
}

fn ensure_file_dir(dir: &Path, count: usize, contents: &[u8]) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let existing = match fs::read_dir(dir) {
        Ok(it) => it.count(),
        Err(e) => return Err(e).with_context(|| format!("readdir {}", dir.display())),
    };
    if existing >= count {
        return Ok(());
    }
    for i in existing..count {
        let p = dir.join(format!("f{:06}", i));
        let mut f = File::create(&p).with_context(|| format!("create {}", p.display()))?;
        if !contents.is_empty() {
            f.write_all(contents)?;
        }
    }
    Ok(())
}
