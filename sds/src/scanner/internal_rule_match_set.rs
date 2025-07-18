use crate::rule_match::InternalRuleMatch;
use crate::{Encoding, Path};

pub struct InternalRuleMatchSet<E: Encoding> {
    // This is a vec of vecs, where each inner vec is a set of matches for a single path.
    list: Vec<(Path<'static>, Vec<InternalRuleMatch<E>>)>,
}

impl<E: Encoding> InternalRuleMatchSet<E> {
    pub fn new() -> Self {
        Self { list: vec![] }
    }

    /// Add a list of rule matches for a path for the first time. The list does NOT need to be sorted.
    pub fn push_new_path_matches(&mut self, path: &Path, list: Vec<InternalRuleMatch<E>>) {
        if list.is_empty() {
            return;
        }
        self.list.push((path.into_static(), list));
    }

    /// Add a new rule match that was generated async (there might already be an existing list of matches for this path)
    pub fn push_async_match(&mut self, path: &Path, rule_match: InternalRuleMatch<E>) {
        if let Some(i) = self.list.iter().position(|(p, _)| p == path) {
            self.list[i].1.push(rule_match);
        } else {
            self.push_new_path_matches(path, vec![rule_match]);
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = (Path<'static>, Vec<InternalRuleMatch<E>>)> {
        self.list.into_iter()
    }
}
