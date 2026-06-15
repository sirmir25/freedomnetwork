//! Domain routing rules — decides whether a connection goes through the bypass
//! pipeline, is passed direct, or is blocked entirely.
//!
//! Rules are loaded from `bypass-rules.txt` in the current directory (or the
//! path given at runtime).  Lines beginning with `#` are comments; empty lines
//! are ignored.  Each non-empty line has the form:
//!
//!   PROXY   rutracker.org
//!   DIRECT  192.168.1.1
//!   BLOCK   ads.example.com
//!
//! Matching is suffix-based (sub-domains inherit the parent rule).
//! Unknown hosts default to `Action::Proxy` so everything is bypassed unless
//! explicitly listed as DIRECT.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Proxy,
    Direct,
    Block,
}

pub struct Rules {
    map: HashMap<String, Action>,
}

impl Rules {
    pub fn load(path: &Path) -> Self {
        let mut map = HashMap::new();
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.splitn(2, char::is_whitespace);
                let keyword = parts.next().unwrap_or("").to_uppercase();
                let domain  = parts.next().unwrap_or("").trim().to_lowercase();
                if domain.is_empty() {
                    continue;
                }
                let action = match keyword.as_str() {
                    "DIRECT" => Action::Direct,
                    "BLOCK"  => Action::Block,
                    _        => Action::Proxy,
                };
                map.insert(domain, action);
            }
        }
        Self { map }
    }

    /// Return the routing action for a hostname.
    /// Walks up the domain hierarchy: `a.b.c` → `b.c` → `c`.
    pub fn action_for(&self, host: &str) -> Action {
        let host = host.to_lowercase();
        let mut s: &str = &host;
        loop {
            if let Some(&a) = self.map.get(s) {
                return a;
            }
            if let Some(dot) = s.find('.') {
                s = &s[dot + 1..];
            } else {
                break;
            }
        }
        Action::Proxy // default: bypass everything
    }

    pub fn global() -> &'static Rules {
        static G: OnceLock<Rules> = OnceLock::new();
        G.get_or_init(|| Rules::load(Path::new("bypass-rules.txt")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn rules_from(text: &str) -> Rules {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{text}").unwrap();
        Rules::load(f.path())
    }

    #[test]
    fn proxy_default() {
        let r = rules_from("DIRECT google.com\n");
        assert_eq!(r.action_for("youtube.com"), Action::Proxy);
    }

    #[test]
    fn direct_exact() {
        let r = rules_from("DIRECT google.com\n");
        assert_eq!(r.action_for("google.com"), Action::Direct);
    }

    #[test]
    fn subdomain_inherits() {
        let r = rules_from("DIRECT google.com\n");
        assert_eq!(r.action_for("mail.google.com"), Action::Direct);
    }

    #[test]
    fn block_action() {
        let r = rules_from("BLOCK ads.example.com\n");
        assert_eq!(r.action_for("ads.example.com"), Action::Block);
    }

    #[test]
    fn comment_ignored() {
        let r = rules_from("# this is a comment\nPROXY rutracker.org\n");
        assert_eq!(r.action_for("rutracker.org"), Action::Proxy);
    }
}
