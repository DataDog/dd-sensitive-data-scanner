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

    /// Verbatim `origin/main` eager-`AHashMap` implementation used as the differential oracle.
    struct MainInternalRuleMatchSet<E: Encoding> {
        sync_matches: Vec<(Path<'static>, Vec<InternalRuleMatch<E>>)>,
        async_matches: AHashMap<Path<'static>, Vec<InternalRuleMatch<E>>>,
    }

    impl<E: Encoding> MainInternalRuleMatchSet<E> {
        fn new() -> Self {
            Self {
                sync_matches: Vec::new(),
                async_matches: AHashMap::new(),
            }
        }

        fn push_sync_matches(&mut self, path: &Path, matches: Vec<InternalRuleMatch<E>>) {
            if matches.is_empty() {
                return;
            }
            self.sync_matches.push((path.into_static(), matches));
        }

        fn is_empty(&self) -> bool {
            self.sync_matches.is_empty() && self.async_matches.is_empty()
        }

        fn push_async_matches(
            &mut self,
            path: &Path,
            matches: impl IntoIterator<Item = InternalRuleMatch<E>>,
        ) {
            let mut matches = matches.into_iter().peekable();
            if matches.peek().is_none() {
                return;
            }
            self.async_matches
                .entry(path.into_static())
                .or_default()
                .extend(matches);
        }

        fn into_iter(mut self) -> impl Iterator<Item = (Path<'static>, Vec<InternalRuleMatch<E>>)> {
            if !self.async_matches.is_empty() {
                for (path, matches) in &mut self.sync_matches {
                    if let Some(async_matches) = self.async_matches.remove(path) {
                        matches.extend(async_matches)
                    }
                }
            }

            self.sync_matches.into_iter().chain(self.async_matches)
        }
    }

    #[test]
    fn differential_randomized_matches_verbatim_main_50k_ops() {
        let mut seed: u64 = 0xfeed_face_cafe_1234;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let paths: Vec<Path<'static>> = (0..40).map(|i| path_of(&format!("field_{i}"))).collect();
        let mut total_ops = 0usize;

        while total_ops < 50_000 {
            let mut actual_set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet::new();
            let mut main_set: MainInternalRuleMatchSet<Utf8Encoding> =
                MainInternalRuleMatchSet::new();

            let path_pool = 1 + (next_u64() as usize) % paths.len();
            let steps = (next_u64() % 32) as usize;
            let mut sync_entries = 0usize;
            let mut saw_non_empty_async = false;

            for step in 0..steps {
                let p = &paths[(next_u64() as usize) % path_pool];
                let count = (next_u64() % 5) as usize;
                let ms_actual: Vec<InternalRuleMatch<Utf8Encoding>> = (0..count)
                    .map(|k| {
                        let id = step * 10 + k;
                        make_match(id, id, id + 1)
                    })
                    .collect();
                let ms_main: Vec<InternalRuleMatch<Utf8Encoding>> = (0..count)
                    .map(|k| {
                        let id = step * 10 + k;
                        make_match(id, id, id + 1)
                    })
                    .collect();

                if next_u64().is_multiple_of(2) {
                    actual_set.push_sync_matches(p, ms_actual);
                    main_set.push_sync_matches(p, ms_main);
                    if count > 0 {
                        sync_entries += 1;
                    }
                } else {
                    actual_set.push_async_matches(p, ms_actual);
                    main_set.push_async_matches(p, ms_main);
                    if count > 0 {
                        saw_non_empty_async = true;
                    }
                }
                assert_eq!(actual_set.is_empty(), main_set.is_empty());
                assert_eq!(actual_set.async_matches.is_some(), saw_non_empty_async);
                total_ops += 1;
            }

            let actual: Vec<(Path<'static>, Vec<usize>)> = actual_set
                .into_iter()
                .map(|(p, ms)| (p, ms.into_iter().map(|m| m.rule_index).collect()))
                .collect();
            let expected: Vec<(Path<'static>, Vec<usize>)> = main_set
                .into_iter()
                .map(|(p, ms)| (p, ms.into_iter().map(|m| m.rule_index).collect()))
                .collect();

            // Sync entries preserve exact order; remaining async-only entries match as a map.
            assert_eq!(actual.len(), expected.len());
            assert_eq!(&actual[..sync_entries], &expected[..sync_entries]);
            let actual_async_tail: BTreeMap<Path<'static>, Vec<usize>> =
                actual[sync_entries..].iter().cloned().collect();
            let expected_async_tail: BTreeMap<Path<'static>, Vec<usize>> =
                expected[sync_entries..].iter().cloned().collect();
            assert_eq!(actual_async_tail, expected_async_tail);
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::{StringMatch, Utf8Encoding};

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

    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_internal_rule_match_set_empty_and_sync_never_allocates_async() {
        let mut set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet::new();
        let root = Path::root();

        let r0: usize = kani::any();
        let r1: usize = kani::any();
        let s0: usize = kani::any();
        let e0: usize = kani::any();
        let s1: usize = kani::any();
        let e1: usize = kani::any();

        // Empty sync and empty async batches must leave `set` empty and NEVER allocate `async_matches`.
        set.push_sync_matches(&root, Vec::new());
        set.push_async_matches(&root, std::iter::empty());
        assert!(set.async_matches.is_none());
        assert!(set.is_empty());

        // Non-empty sync batches must also leave `async_matches == None` and preserve order/values.
        set.push_sync_matches(&root, vec![make_match(r0, s0, e0)]);
        set.push_async_matches(&root, std::iter::empty());
        set.push_sync_matches(&root, vec![make_match(r1, s1, e1)]);
        assert!(set.async_matches.is_none());
        assert!(!set.is_empty());

        let mut iter = set.into_iter();
        let (_p0, m0) = iter.next().unwrap();
        assert_eq!(m0.len(), 1);
        assert_eq!(m0[0].rule_index, r0);
        assert_eq!(m0[0].utf8_start, s0);
        assert_eq!(m0[0].utf8_end, e0);

        let (_p1, m1) = iter.next().unwrap();
        assert_eq!(m1.len(), 1);
        assert_eq!(m1[0].rule_index, r1);
        assert_eq!(m1[0].utf8_start, s1);
        assert_eq!(m1[0].utf8_end, e1);

        assert!(iter.next().is_none());
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_internal_rule_match_set_some_empty_async_map_equivalence() {
        // Verify `is_empty()` and `into_iter()` treat `Some(empty_map)` identically to `None`:
        // `is_empty()` returns true when sync is empty and false after a sync push, and
        // `InternalRuleMatchSetIter::next()` drains sync entries then cleanly terminates on
        // `Some(empty_async_iter)`.
        let mut set: InternalRuleMatchSet<Utf8Encoding> = InternalRuleMatchSet {
            sync_matches: Vec::with_capacity(1),
            async_matches: Some(AHashMap::with_capacity_and_hasher(
                0,
                ahash::RandomState::with_seeds(1, 2, 3, 4),
            )),
        };
        let path_a = Path::root();

        assert!(set.is_empty());

        let r_sync: usize = kani::any();
        let start: usize = kani::any();
        let end: usize = kani::any();
        set.push_sync_matches(&path_a, vec![make_match(r_sync, start, end)]);
        set.push_async_matches(&path_a, std::iter::empty());
        assert!(!set.is_empty());

        let mut iter = set.into_iter();
        let (p0, ms0) = iter.next().unwrap();
        assert!(p0 == path_a);
        assert_eq!(ms0.len(), 1);
        assert_eq!(ms0[0].rule_index, r_sync);
        assert_eq!(ms0[0].utf8_start, start);
        assert_eq!(ms0[0].utf8_end, end);
        assert!(iter.next().is_none());
        kani::cover!(true, "post-assertion conclusion reachable");
    }
}
