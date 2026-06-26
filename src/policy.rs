use globset::{Glob, GlobSet, GlobSetBuilder};

#[derive(Debug, Clone)]
pub struct Policy {
    allow: Option<GlobSet>,
    deny: GlobSet,
    readonly: bool,
}

impl Policy {
    pub fn new(allow: &[String], deny: &[String]) -> anyhow::Result<Self> {
        Self::with_readonly(allow, deny, false)
    }

    pub fn with_readonly(
        allow: &[String],
        deny: &[String],
        readonly: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            allow: build_optional_set(allow)?,
            deny: build_set(deny)?,
            readonly,
        })
    }

    pub fn permits(&self, path: &str) -> bool {
        if self.deny.is_match(path) {
            return false;
        }

        match &self.allow {
            Some(allow) => allow.is_match(path),
            None => true,
        }
    }

    pub fn permits_write(&self, path: &str) -> bool {
        if self.readonly {
            return false;
        }
        self.permits(path)
    }
}

fn build_optional_set(patterns: &[String]) -> anyhow::Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    Ok(Some(build_set(patterns)?))
}

fn build_set(patterns: &[String]) -> anyhow::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(p: &str) -> String {
        p.to_string()
    }

    #[test]
    fn permits_denies_globbed_path() {
        let policy = Policy::new(&[], &[s("/secret/**")]).unwrap();
        assert!(
            !policy.permits("/secret/x.txt"),
            "direct child should be denied"
        );
        assert!(
            !policy.permits("/secret/sub/y.txt"),
            "nested path should be denied"
        );
        assert!(
            policy.permits("/public/z.txt"),
            "unmatched path should be allowed"
        );
    }

    #[test]
    fn permits_allows_when_no_deny() {
        let policy = Policy::new(&[], &[]).unwrap();
        assert!(policy.permits("/anything/at/all"));
    }

    #[test]
    fn permits_allow_list_restricts() {
        // With an allowlist, only matching paths pass even without deny patterns.
        let policy = Policy::new(&[s("/workspace/**")], &[]).unwrap();
        assert!(policy.permits("/workspace/file.txt"));
        assert!(
            !policy.permits("/etc/passwd"),
            "outside allowlist should be denied"
        );
    }

    #[test]
    fn deny_overrides_allow() {
        // A path inside the allowlist but also matched by deny must be blocked.
        let policy = Policy::new(&[s("/workspace/**")], &[s("/workspace/secret/**")]).unwrap();
        assert!(policy.permits("/workspace/ok.txt"));
        assert!(!policy.permits("/workspace/secret/creds.txt"));
    }

    #[test]
    fn readonly_blocks_writes_but_not_reads() {
        let policy = Policy::with_readonly(&[], &[], true).unwrap();
        assert!(
            policy.permits("/anything.txt"),
            "reads must still be permitted under readonly"
        );
        assert!(
            !policy.permits_write("/anything.txt"),
            "writes must be blocked under readonly"
        );
    }

    #[test]
    fn readwrite_allows_writes() {
        let policy = Policy::with_readonly(&[], &[], false).unwrap();
        assert!(policy.permits("/anything.txt"));
        assert!(
            policy.permits_write("/anything.txt"),
            "writes must be permitted when not readonly"
        );
    }

    #[test]
    fn deny_blocks_writes_even_when_not_readonly() {
        let policy = Policy::with_readonly(&[], &[s("/secret/**")], false).unwrap();
        assert!(
            !policy.permits_write("/secret/x.txt"),
            "deny patterns must apply to writes too"
        );
        assert!(
            policy.permits_write("/public/x.txt"),
            "non-denied paths must be writable"
        );
    }

    #[test]
    fn new_defaults_to_readwrite_for_back_compat() {
        // Existing callers that haven't been updated to with_readonly should
        // keep the historical behavior of allowing writes — readonly is
        // opt-in.
        let policy = Policy::new(&[], &[]).unwrap();
        assert!(policy.permits_write("/x.txt"));
    }
}
