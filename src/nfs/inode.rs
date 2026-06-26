//! NFSv3 file-handle ↔ store-path interning.
//!
//! NFS addresses every object by an opaque `fileid3` (u64). The kernel client
//! looks up children by name from a parent id, so we own the mapping between
//! ids we hand out and the `Store` paths we resolve them to. Lives in its own
//! module because it's pure data — no Store / Policy / Audit coupling.

use parking_lot::Mutex;
use std::collections::HashMap;

/// File-id 0 is reserved by RFC 1813. Root is 1 by convention.
pub const ROOT_ID: u64 = 1;

pub struct Inodes {
    inner: Mutex<Inner>,
}

struct Inner {
    next: u64,
    by_path: HashMap<String, u64>,
    by_id: HashMap<u64, String>,
}

impl Inodes {
    pub fn new() -> Self {
        let mut by_path = HashMap::new();
        let mut by_id = HashMap::new();
        by_path.insert(String::new(), ROOT_ID);
        by_id.insert(ROOT_ID, String::new());
        Self {
            inner: Mutex::new(Inner {
                next: ROOT_ID + 1,
                by_path,
                by_id,
            }),
        }
    }

    /// Return the existing id for `path` or allocate a new one.
    pub fn intern(&self, path: &str) -> u64 {
        let mut g = self.inner.lock();
        if let Some(id) = g.by_path.get(path) {
            return *id;
        }
        let id = g.next;
        g.next += 1;
        g.by_path.insert(path.to_string(), id);
        g.by_id.insert(id, path.to_string());
        id
    }

    pub fn path_of(&self, id: u64) -> Option<String> {
        self.inner.lock().by_id.get(&id).cloned()
    }
}

impl Default for Inodes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_one_and_empty_path() {
        let i = Inodes::new();
        assert_eq!(i.intern(""), ROOT_ID);
        assert_eq!(i.path_of(ROOT_ID).as_deref(), Some(""));
    }

    #[test]
    fn intern_is_idempotent() {
        let i = Inodes::new();
        let a = i.intern("dir/file.txt");
        let b = i.intern("dir/file.txt");
        assert_eq!(a, b);
        assert!(a > ROOT_ID);
    }

    #[test]
    fn distinct_paths_get_distinct_ids() {
        let i = Inodes::new();
        let a = i.intern("a");
        let b = i.intern("b");
        assert_ne!(a, b);
        assert_eq!(i.path_of(a).as_deref(), Some("a"));
        assert_eq!(i.path_of(b).as_deref(), Some("b"));
    }
}
