use crate::rule_match::InternalRuleMatch;
use crate::{Encoding, Path};
use ahash::AHashMap;

pub struct InternalRuleMatchSet<E: Encoding> {
    // This is a maps of vecs, where each inner vec is a set of matches for a single path.
    map: AHashMap<Path<'static>, Vec<InternalRuleMatch<E>>>,
}

impl<E: Encoding> InternalRuleMatchSet<E> {
    pub fn new() -> Self {
        Self {
            map: AHashMap::new(),
        }
    }

    pub fn push_matches(
        &mut self,
        path: &Path,
        list: impl IntoIterator<Item = InternalRuleMatch<E>>,
    ) {
        let mut list = list.into_iter().peekable();
        if list.peek().is_none() {
            // An empty list should not push a new entry in the map
            return;
        }
        self.map.entry(path.into_static()).or_default().extend(list);
    }

    pub fn into_iter(self) -> impl Iterator<Item = (Path<'static>, Vec<InternalRuleMatch<E>>)> {
        self.map.into_iter()
    }
}
