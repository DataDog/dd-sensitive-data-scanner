use crate::rule_match::InternalRuleMatch;
use crate::{Encoding, Path};
use ahash::AHashMap;

pub struct InternalRuleMatchSet<E: Encoding> {
    sync_matches: Vec<(Path<'static>, Vec<InternalRuleMatch<E>>)>,
    // Lazily allocated on the first non-empty async match batch so sync-only scans
    // never seed an AHashMap.
    async_matches: Option<AHashMap<Path<'static>, Vec<InternalRuleMatch<E>>>>,
}

impl<E: Encoding> InternalRuleMatchSet<E> {
    #[inline]
    pub fn new() -> Self {
        Self {
            sync_matches: Vec::new(),
            async_matches: None,
        }
    }

    pub fn push_sync_matches(&mut self, path: &Path, matches: Vec<InternalRuleMatch<E>>) {
        if matches.is_empty() {
            return;
        }
        self.sync_matches.push((path.into_static(), matches));
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.sync_matches.is_empty()
            && self
                .async_matches
                .as_ref()
                .is_none_or(|matches| matches.is_empty())
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
            .get_or_insert_with(AHashMap::new)
            .entry(path.into_static())
            .or_default()
            .extend(matches);
    }

    #[inline]
    pub fn into_iter(mut self) -> impl Iterator<Item = (Path<'static>, Vec<InternalRuleMatch<E>>)> {
        if let Some(async_matches) = self.async_matches.as_mut()
            && !async_matches.is_empty()
        {
            // merge async matches into sync matches if there are matches for the same path
            for (path, matches) in &mut self.sync_matches {
                if let Some(path_async_matches) = async_matches.remove(path) {
                    matches.extend(path_async_matches);
                }
            }
        }

        InternalRuleMatchSetIter {
            sync: self.sync_matches.into_iter(),
            async_matches: self.async_matches.map(IntoIterator::into_iter),
        }
    }
}

struct InternalRuleMatchSetIter<E: Encoding> {
    sync: std::vec::IntoIter<(Path<'static>, Vec<InternalRuleMatch<E>>)>,
    async_matches:
        Option<std::collections::hash_map::IntoIter<Path<'static>, Vec<InternalRuleMatch<E>>>>,
}

impl<E: Encoding> Iterator for InternalRuleMatchSetIter<E> {
    type Item = (Path<'static>, Vec<InternalRuleMatch<E>>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.sync.next() {
            return Some(item);
        }
        self.async_matches.as_mut()?.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PathSegment, StringMatch, Utf8Encoding};
    use std::collections::BTreeMap;

    fn make_match(rule_index: usize, start: usize, end: usize) -> InternalRuleMatch<Utf8Encoding> {
        InternalRuleMatch::new(
            rule_index,
            StringMatch {
                start,
                end,
                keyword: None,
            },
        )
    }

    fn path_of(field: &str) -> Path<'static> {
        Path::from(vec![PathSegment::Field(field.to_string().into())])
    }

    #[test]
    fn empty_set_keeps_async_map_unallocated() {
        let mut set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet::new();
        assert!(set.is_empty());
        assert!(set.async_matches.is_none());

        set.push_sync_matches(&path_of("a"), vec![]);
        set.push_async_matches(&path_of("a"), std::iter::empty());
        assert!(set.is_empty());
        assert!(set.async_matches.is_none());
        assert_eq!(set.into_iter().count(), 0);
    }

    #[test]
    fn sync_only_matches_never_allocate_async_map() {
        let mut set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet::new();
        set.push_sync_matches(&path_of("a"), vec![make_match(0, 0, 3)]);
        set.push_sync_matches(&path_of("b"), vec![make_match(1, 2, 5)]);
        assert!(!set.is_empty());
        assert!(set.async_matches.is_none());

        let collected: Vec<(Path<'static>, Vec<usize>)> = set
            .into_iter()
            .map(|(p, ms)| (p, ms.into_iter().map(|m| m.rule_index).collect()))
            .collect();
        assert_eq!(
            collected,
            vec![(path_of("a"), vec![0]), (path_of("b"), vec![1])]
        );
    }

    #[test]
    fn async_only_matches_accumulate_per_path() {
        let mut set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet::new();
        set.push_async_matches(&path_of("a"), [make_match(1, 0, 2)]);
        set.push_async_matches(&path_of("a"), [make_match(2, 3, 5), make_match(3, 6, 8)]);
        set.push_async_matches(&path_of("b"), [make_match(4, 1, 4)]);
        assert!(!set.is_empty());
        assert!(set.async_matches.is_some());

        let collected: BTreeMap<Path<'static>, Vec<usize>> = set
            .into_iter()
            .map(|(p, ms)| (p, ms.into_iter().map(|m| m.rule_index).collect()))
            .collect();
        assert_eq!(collected.get(&path_of("a")), Some(&vec![1, 2, 3]));
        assert_eq!(collected.get(&path_of("b")), Some(&vec![4]));
    }

    #[test]
    fn sync_and_async_matches_merge_same_path_and_keep_disjoint_paths() {
        let mut set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet::new();
        set.push_sync_matches(&path_of("shared"), vec![make_match(0, 0, 2)]);
        set.push_sync_matches(&path_of("sync_only"), vec![make_match(1, 0, 2)]);
        set.push_async_matches(&path_of("shared"), [make_match(2, 3, 5)]);
        set.push_async_matches(&path_of("async_only"), [make_match(3, 1, 4)]);

        let collected: BTreeMap<Path<'static>, Vec<usize>> = set
            .into_iter()
            .map(|(p, ms)| (p, ms.into_iter().map(|m| m.rule_index).collect()))
            .collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected.get(&path_of("shared")), Some(&vec![0, 2]));
        assert_eq!(collected.get(&path_of("sync_only")), Some(&vec![1]));
        assert_eq!(collected.get(&path_of("async_only")), Some(&vec![3]));
    }

    #[test]
    fn differential_randomized_matches_eager_map_oracle() {
        let mut seed: u64 = 0xfeed_face_cafe_1234;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let paths: Vec<Path<'static>> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|f| path_of(f))
            .collect();

        for _trial in 0..300 {
            let mut set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet::new();
            let mut oracle_sync: Vec<(Path<'static>, Vec<usize>)> = Vec::new();
            let mut oracle_async: AHashMap<Path<'static>, Vec<usize>> = AHashMap::new();

            let steps = (next_u64() % 16) as usize;
            for step in 0..steps {
                let p = &paths[(next_u64() as usize) % paths.len()];
                let count = (next_u64() % 4) as usize;
                let ids: Vec<usize> = (0..count).map(|k| step * 10 + k).collect();
                let ms: Vec<InternalRuleMatch<Utf8Encoding>> =
                    ids.iter().map(|&id| make_match(id, id, id + 1)).collect();

                if next_u64().is_multiple_of(2) {
                    set.push_sync_matches(p, ms);
                    if !ids.is_empty() {
                        oracle_sync.push((p.into_static(), ids));
                    }
                } else {
                    set.push_async_matches(p, ms);
                    if !ids.is_empty() {
                        oracle_async.entry(p.into_static()).or_default().extend(ids);
                    }
                }
                assert_eq!(
                    set.is_empty(),
                    oracle_sync.is_empty() && oracle_async.is_empty()
                );
            }

            if !oracle_async.is_empty() {
                for (path, matches) in &mut oracle_sync {
                    if let Some(am) = oracle_async.remove(path) {
                        matches.extend(am);
                    }
                }
            }

            let actual: Vec<(Path<'static>, Vec<usize>)> = set
                .into_iter()
                .map(|(p, ms)| (p, ms.into_iter().map(|m| m.rule_index).collect()))
                .collect();

            // Sync entries preserve exact order; remaining async-only entries match as a map.
            let sync_len = oracle_sync.len();
            assert_eq!(&actual[..sync_len], &oracle_sync[..]);
            let actual_async_tail: BTreeMap<Path<'static>, Vec<usize>> =
                actual[sync_len..].iter().cloned().collect();
            let expected_async_tail: BTreeMap<Path<'static>, Vec<usize>> =
                oracle_async.into_iter().collect();
            assert_eq!(actual_async_tail, expected_async_tail);
        }
    }
}
