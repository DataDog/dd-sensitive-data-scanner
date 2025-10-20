use crate::rule_match::InternalRuleMatch;
use crate::{Encoding, Path};
use ahash::AHashMap;

pub struct InternalRuleMatchSet<E: Encoding> {
    sync_matches: Vec<(Path<'static>, Vec<InternalRuleMatch<E>>)>,
    // This is a maps of vecs, where each inner vec is a set of matches for a single path.
    async_matches: AHashMap<Path<'static>, Vec<InternalRuleMatch<E>>>,
}

impl<E: Encoding> InternalRuleMatchSet<E> {
    pub fn new() -> Self {
        Self {
            sync_matches: Vec::new(),
            async_matches: AHashMap::new(),
        }
    }

    pub fn push_sync_matches(&mut self, path: &Path, matches: Vec<InternalRuleMatch<E>>) {
        if matches.is_empty() {
            return;
        }
        self.sync_matches.push((path.into_static(), matches));
    }

    pub fn is_empty(&self) -> bool {
        self.sync_matches.is_empty() && self.async_matches.is_empty()
    }

    pub fn push_async_matches(
        &mut self,
        path: &Path,
        matches: impl IntoIterator<Item = InternalRuleMatch<E>>,
    ) {
        let mut matches = matches.into_iter().peekable();
        if matches.peek().is_none() {
            // An empty list should not push a new entry in the map
            return;
        }
        self.async_matches
            .entry(path.into_static())
            .or_default()
            .extend(matches);
    }

    pub fn into_iter(mut self) -> impl Iterator<Item = (Path<'static>, Vec<InternalRuleMatch<E>>)> {
        if !self.async_matches.is_empty() {
            // merge async matches into sync matches if there are matches for the same path
            for (path, matches) in &mut self.sync_matches {
                if let Some(async_matches) = self.async_matches.remove(path) {
                    matches.extend(async_matches)
                }
            }
        }

        self.sync_matches.into_iter().chain(self.async_matches)
    }
}
