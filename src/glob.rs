//! Minimal top-level glob expansion (single directory component).
//!
//! Supports `*`, `?` and `[...]` within one path component — enough for
//! sentinel globs like `/var/tmp/*.final`. No `**`, no recursion: sentinel
//! sets are flat by design.

use std::path::{Path, PathBuf};

fn has_meta(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// Compile a glob body (one path component) into a regex string.
fn glob_component_to_regex(g: &str) -> String {
    let mut out = String::from("^");
    let mut chars = g.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            '[' => {
                let mut class = String::from("[");
                if chars.peek().copied() == Some('!') {
                    chars.next();
                    class.push('^');
                }
                for c2 in chars.by_ref() {
                    if c2 == ']' {
                        break;
                    }
                    if "\\^]-".contains(c2) {
                        class.push('\\');
                    }
                    class.push(c2);
                }
                class.push(']');
                out.push_str(&class);
            }
            c if "\\.+(){}|^$" .contains(c) => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push('$');
    out
}

/// Split a pattern into the literal base directory and the component glob.
fn split_pattern(pattern: &str) -> (PathBuf, String) {
    let mut base = if pattern.starts_with('/') {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    let mut tail = String::new();
    for comp in pattern.split('/') {
        if comp.is_empty() {
            continue;
        }
        if tail.is_empty() && !has_meta(comp) {
            base.push(comp);
        } else {
            if !tail.is_empty() {
                tail.push('/');
            }
            tail.push_str(comp);
        }
    }
    (base, tail)
}

/// Expand a glob to existing paths (unsorted).
#[must_use]
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let (base, tail) = split_pattern(pattern);
    if tail.is_empty() {
        // Literal path: return it when it exists.
        return if Path::new(&base).exists() {
            vec![base]
        } else {
            Vec::new()
        };
    }
    let re = match regex::Regex::new(&glob_component_to_regex(&tail)) {
        Ok(re) => re,
        Err(_) => return Vec::new(),
    };
    let dir: PathBuf = if base.as_os_str().is_empty() {
        Path::new(".").to_path_buf()
    } else {
        base
    };
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if re.is_match(&name) {
            out.push(e.path());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_single_component_globs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.final"), "").unwrap();
        std::fs::write(tmp.path().join("b.done"), "").unwrap();
        std::fs::write(tmp.path().join("c.txt"), "").unwrap();
        let pat = tmp.path().join("*.final").to_string_lossy().to_string();
        assert_eq!(expand(&pat), vec![tmp.path().join("a.final")]);
        let pat2 = tmp.path().join("[ab].*").to_string_lossy().to_string();
        let mut got = expand(&pat2);
        got.sort();
        assert_eq!(
            got,
            vec![tmp.path().join("a.final"), tmp.path().join("b.done")]
        );
    }

    #[test]
    fn missing_dir_is_empty_not_error() {
        assert!(expand("/nonexistent-dir-xyz/*.final").is_empty());
    }
}
