use anyhow::{bail, Result};

/// Rules for selecting paths in a sync tree.
///
/// Patterns are intentionally small and portable. A pattern without `/` matches
/// a basename anywhere; `*` and `?` do not cross `/`, while `**` does. An empty
/// include list means "include everything". Exclusions are evaluated last and
/// therefore win over an include.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncSelection {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl SyncSelection {
    pub fn all() -> Self {
        Self::default()
    }

    pub fn new(
        include: impl IntoIterator<Item = impl Into<String>>,
        exclude: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let include = normalize_patterns(include.into_iter().map(Into::into).collect())?;
        let exclude = normalize_patterns(exclude.into_iter().map(Into::into).collect())?;
        Ok(Self { include, exclude })
    }

    pub fn from_csv(include: Option<&str>, exclude: Option<&str>) -> Result<Self> {
        let parse = |value: Option<&str>| -> Result<Vec<String>> {
            Ok(value
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect())
        };
        Self::new(parse(include)?, parse(exclude)?)
    }

    pub fn is_all(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    pub fn includes(&self) -> &[String] {
        &self.include
    }

    pub fn excludes(&self) -> &[String] {
        &self.exclude
    }

    pub fn allows_path(&self, path: &str) -> bool {
        let path = normalize_path(path);
        if self.matches_list(&self.exclude, &path) {
            return false;
        }
        self.include.is_empty() || self.matches_list(&self.include, &path)
    }

    /// Whether a directory should be traversed. A directory can be traversed
    /// even when it is not itself selected so a descendant include can match.
    pub fn allows_traversal(&self, path: &str, is_dir: bool) -> bool {
        let path = normalize_path(path);
        if self.matches_list(&self.exclude, &path) {
            return false;
        }
        if !is_dir {
            return self.allows_path(&path);
        }
        self.include.is_empty()
            || self.matches_list(&self.include, &path)
            || self
                .include
                .iter()
                .any(|pattern| pattern_may_have_descendant(pattern, &path))
    }

    fn matches_list(&self, patterns: &[String], path: &str) -> bool {
        patterns.iter().any(|pattern| {
            let basename_only = !pattern.contains('/');
            let candidate = if basename_only {
                path.rsplit('/').next().unwrap_or(path)
            } else {
                path
            };
            wildcard_match(pattern, candidate)
        })
    }
}

fn normalize_patterns(mut patterns: Vec<String>) -> Result<Vec<String>> {
    patterns.sort();
    patterns.dedup();
    for pattern in &patterns {
        if pattern.starts_with('/') || pattern.split('/').any(|part| part == "..") {
            bail!(
                "selection pattern must be relative and cannot contain a '..' component: {pattern}"
            );
        }
    }
    Ok(patterns)
}

fn normalize_path(path: &str) -> String {
    path.trim_matches('/').replace('\\', "/")
}

fn pattern_may_have_descendant(pattern: &str, directory: &str) -> bool {
    if !pattern.contains('/') {
        return true;
    }
    if pattern == "**" || pattern.starts_with("**/") {
        return true;
    }
    if let Some(prefix) = pattern.split('/').next() {
        if prefix == "**" {
            return true;
        }
        if wildcard_match(prefix, directory.split('/').next().unwrap_or_default()) {
            return true;
        }
    }
    directory.is_empty() || pattern.starts_with(&format!("{directory}/"))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        if value == prefix {
            return true;
        }
    }
    fn matches(pattern: &[u8], value: &[u8]) -> bool {
        if pattern.is_empty() {
            return value.is_empty();
        }
        if pattern == b"**" {
            return true;
        }
        if pattern.starts_with(b"**/") {
            return matches(&pattern[3..], value)
                || value
                    .iter()
                    .position(|byte| *byte == b'/')
                    .map(|separator| matches(pattern, &value[separator + 1..]))
                    .unwrap_or(false);
        }
        if value.is_empty() {
            return pattern.iter().all(|byte| *byte == b'*');
        }
        match pattern[0] {
            b'?' if value[0] != b'/' => matches(&pattern[1..], &value[1..]),
            b'*' if pattern.get(1) != Some(&b'*') => {
                (value[0] != b'/' && matches(&pattern[1..], value))
                    || (value[0] != b'/' && matches(pattern, &value[1..]))
            }
            byte if byte == value[0] => matches(&pattern[1..], &value[1..]),
            _ => false,
        }
    }

    matches(pattern.as_bytes(), value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_excludes_and_descendant_rules() {
        let selection = SyncSelection::new(["docs/**", "*.txt"], ["private/**", "*.tmp"]).unwrap();
        assert!(selection.allows_path("docs/readme.md"));
        assert!(selection.allows_path("notes.txt"));
        assert!(!selection.allows_path("notes.tmp"));
        assert!(!selection.allows_path("private/key.txt"));
        assert!(selection.allows_traversal("docs", true));
        assert!(selection.allows_traversal("src", true));
    }

    #[test]
    fn double_star_matches_slashes() {
        assert!(wildcard_match("a/**/b", "a/x/y/b"));
        assert!(wildcard_match("a/**/b", "a/b"));
        assert!(!wildcard_match("a/*/b", "a/x/y/b"));
    }
}
