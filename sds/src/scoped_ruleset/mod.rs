pub(crate) mod bool_set;

use crate::event::{EventVisitor, VisitStringResult};
use crate::scanner::scope::{ScanArea, Scope};
use crate::scoped_ruleset::bool_set::{BoolSet, InlineBitBuffer, clear_bit, contains_bit, set_bit};
use crate::{Event, Path, PathSegment, ScannerError};
use ahash::AHashMap;

pub(crate) const INLINE_STACK_CAPACITY: usize = 16;

/// Small stack of `Copy` items backed by an inline fixed-size array that spills to a heap `Vec`
/// only when length exceeds `N`.
pub(crate) enum InlineStack<T: Copy, const N: usize> {
    Empty,
    Inline { buf: [T; N], len: usize },
    Heap(Vec<T>),
}

impl<T: Copy, const N: usize> InlineStack<T, N> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self::Empty
    }

    #[inline]
    pub(crate) fn with_first(first: T) -> Self {
        const {
            assert!(N > 0, "InlineStack inline capacity must be > 0");
        };
        Self::Inline {
            buf: [first; N],
            len: 1,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Inline { len, .. } => *len,
            Self::Heap(vec) => vec.len(),
        }
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub(crate) fn push(&mut self, value: T) {
        const {
            assert!(N > 0, "InlineStack inline capacity must be > 0");
        };
        match self {
            Self::Empty => {
                *self = Self::Inline {
                    buf: [value; N],
                    len: 1,
                };
            }
            Self::Inline { buf, len } => {
                if *len < N {
                    buf[*len] = value;
                    *len += 1;
                } else {
                    let mut vec = Vec::with_capacity(N * 2);
                    vec.extend_from_slice(&buf[..*len]);
                    vec.push(value);
                    *self = Self::Heap(vec);
                }
            }
            Self::Heap(vec) => vec.push(value),
        }
    }

    #[inline]
    pub(crate) fn pop(&mut self) -> Option<T> {
        match self {
            Self::Empty => None,
            Self::Inline { buf, len } => {
                if *len == 0 {
                    None
                } else {
                    *len -= 1;
                    Some(buf[*len])
                }
            }
            Self::Heap(vec) => vec.pop(),
        }
    }

    #[inline]
    pub(crate) fn truncate(&mut self, new_len: usize) {
        match self {
            Self::Empty => {}
            Self::Inline { len, .. } => {
                if new_len < *len {
                    *len = new_len;
                }
            }
            Self::Heap(vec) => vec.truncate(new_len),
        }
    }

    #[inline]
    pub(crate) fn last(&self) -> Option<&T> {
        match self {
            Self::Empty => None,
            Self::Inline { buf, len } => {
                if *len == 0 {
                    None
                } else {
                    Some(&buf[*len - 1])
                }
            }
            Self::Heap(vec) => vec.last(),
        }
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[T] {
        match self {
            Self::Empty => &[],
            Self::Inline { buf, len } => &buf[..*len],
            Self::Heap(vec) => vec.as_slice(),
        }
    }
}

/// A `ScopedRuleSet` determines which rules will be used to scan each field of an event, and which
/// paths are considered `excluded`.
#[derive(Debug)]
pub struct ScopedRuleSet {
    tree: RuleTree,
    // The number of rules stored in this set
    num_rules: usize,
    add_implicit_index_wildcards: bool,
}

impl ScopedRuleSet {
    /// The scopes for each rule. The indices of the scopes MUST match the rule index.
    pub fn new(rules_scopes: &[Scope]) -> Self {
        let mut tree = RuleTree::new();

        for (rule_index, scope) in rules_scopes.iter().enumerate() {
            match &scope.include {
                ScanArea::Everything => tree.insert_rule_add(&Path::root(), rule_index),
                ScanArea::Only(paths) => {
                    for path in paths {
                        tree.insert_rule_add(path, rule_index);
                    }
                }
            }
            for path in &scope.exclude {
                tree.insert_rule_removal(path, rule_index);
            }
        }
        Self {
            tree,
            num_rules: rules_scopes.len(),
            add_implicit_index_wildcards: false,
        }
    }

    pub fn with_implicit_index_wildcards(mut self, value: bool) -> Self {
        self.add_implicit_index_wildcards = value;
        self
    }

    pub fn visit_string_rule_combinations<'path, 'c: 'path>(
        &'c self,
        event: &'path mut impl Event,
        content_visitor: impl ContentVisitor<'path>,
    ) -> Result<(), ScannerError> {
        let mut active_removal_sets = InlineStack::new();
        let root_has_removals = !self.tree.removed_rules.is_empty();
        if root_has_removals {
            active_removal_sets.push(&self.tree.removed_rules);
        }
        let root_has_adds = !self.tree.added_rules.is_empty();
        let mut visitor = ScopedRuledSetEventVisitor {
            content_visitor,
            tree_nodes: InlineStack::with_first(ActiveRuleTree {
                rule_tree: &self.tree,
                index_wildcard_match: false,
            }),
            active_node_counter: InlineStack::with_first(NodeCounter {
                active_tree_count: 1,
                active_removal_count: u32::from(root_has_removals),
                active_add_node_count: u32::from(root_has_adds),
            }),
            active_removal_sets,
            combined_exclusions: InlineBitBuffer::new(),
            combined_exclusions_dirty: true,
            path: Path::root(),
            bool_set: None,
            num_rules: self.num_rules,
            total_active_add_nodes: usize::from(root_has_adds),
            wildcard_segment_depth: 0,
            add_implicit_index_wildcards: self.add_implicit_index_wildcards,
        };

        event.visit_event(&mut visitor)
    }
}

pub struct ExclusionCheck<'a> {
    excluded_words: &'a [u64],
}

impl ExclusionCheck<'_> {
    #[inline]
    pub fn is_excluded(&self, rule_index: usize) -> bool {
        contains_bit(self.excluded_words, rule_index)
    }
}

pub trait ContentVisitor<'path> {
    fn visit_content<'content_visitor>(
        &'content_visitor mut self,
        path: &Path<'path>,
        content: &str,
        rules: RuleIndexVisitor,
        is_excluded: ExclusionCheck<'content_visitor>,
    ) -> Result<bool, ScannerError>;
}

// This is just a reference to a RuleTree with some additional information
#[derive(Clone, Copy)]
struct ActiveRuleTree<'a> {
    rule_tree: &'a RuleTree,
    // If this tree was pushed because of a wildcard index, indices aren't
    // allowed to match immediately after, so they are ignored.
    index_wildcard_match: bool,
}

#[derive(Clone, Copy)]
struct NodeCounter {
    // This counts how many trees are currently active, which can
    // happen due to (implicit) wildcard segments. The last value in this
    // list is the current number of active trees (n), which is the last
    // n trees in `tree_nodes`.
    active_tree_count: usize,
    // Number of non-empty `removed_rules` slices pushed onto `active_removal_sets`
    // at this path depth.
    active_removal_count: u32,
    // Number of non-wildcard nodes with non-empty `added_rules` pushed at this depth.
    active_add_node_count: u32,
}

struct ScopedRuledSetEventVisitor<'a, C> {
    // The struct that will receive content / rules.
    content_visitor: C,

    // This is a list of parent tree nodes, which is a list of all of the "active" rule changes.
    // If an "Add" exists for a rule in this list, it will be scanned. If a single "Remove" exists, it will cause the `ExclusionCheck` to return true.
    tree_nodes: InlineStack<ActiveRuleTree<'a>, INLINE_STACK_CAPACITY>,

    // This is a counter that helps keep track of how many elements we have pushed
    // in `tree_nodes` and `active_removal_sets` at each segment depth.
    active_node_counter: InlineStack<NodeCounter, INLINE_STACK_CAPACITY>,

    // Active non-empty exclusion bitsets along the current path (excluding wildcard duplicates,
    // whose underlying `RuleTree` is already earlier on the stack).
    active_removal_sets: InlineStack<&'a Vec<u64>, INLINE_STACK_CAPACITY>,

    // Reusable union buffer used only when two or more active nodes define exclusions.
    combined_exclusions: InlineBitBuffer,
    combined_exclusions_dirty: bool,

    // The current path being visited
    path: Path<'a>,

    // Lazily created boolean set to de-duplicate rules only when implicit index wildcards
    // can actually produce duplicate rule indices (wildcard depth > 0 and >1 active add node).
    bool_set: Option<BoolSet>,
    num_rules: usize,
    total_active_add_nodes: usize,
    wildcard_segment_depth: usize,

    add_implicit_index_wildcards: bool,
}

impl<'path, C> EventVisitor<'path> for ScopedRuledSetEventVisitor<'path, C>
where
    C: ContentVisitor<'path>,
{
    fn push_segment(&mut self, segment: PathSegment<'path>) {
        // update the tree
        // The current path may go beyond what is stored in the "include" tree, so the tree is only updated if they are at the same height.

        let num_active_trees = self.active_node_counter.last().unwrap().active_tree_count;
        let tree_nodes_len = self.tree_nodes.len();
        let removal_sets_len = self.active_removal_sets.len();
        let active_trees_range = tree_nodes_len - num_active_trees..tree_nodes_len;
        let is_wildcard_index = self.add_implicit_index_wildcards && segment.is_index();
        let mut added_nodes_at_level = 0usize;

        for tree_index in active_trees_range {
            let active_tree = self.tree_nodes.as_slice()[tree_index];
            if (!active_tree.index_wildcard_match || !segment.is_index())
                && let Some(child) = active_tree.rule_tree.children.get(&segment)
            {
                self.tree_nodes.push(ActiveRuleTree {
                    rule_tree: child,
                    index_wildcard_match: false,
                });
                if !child.added_rules.is_empty() {
                    added_nodes_at_level += 1;
                }
                if !child.removed_rules.is_empty() {
                    self.active_removal_sets.push(&child.removed_rules);
                }
            }

            if is_wildcard_index {
                // Optionally skip the index (it acts as a wildcard) by
                // pushing the same tree back onto the stack.
                // `active_tree.rule_tree` is already present earlier on `tree_nodes`, so its
                // `removed_rules` (if non-empty) are already tracked in `active_removal_sets`.
                self.tree_nodes.push(ActiveRuleTree {
                    rule_tree: active_tree.rule_tree,
                    index_wildcard_match: true,
                });
            }
        }

        if is_wildcard_index {
            self.wildcard_segment_depth += 1;
        }
        self.total_active_add_nodes += added_nodes_at_level;

        let active_removal_count = self.active_removal_sets.len() - removal_sets_len;
        if active_removal_count > 0 {
            self.combined_exclusions_dirty = true;
        }

        // The new number of active trees is the number of new trees pushed
        self.active_node_counter.push(NodeCounter {
            active_tree_count: self.tree_nodes.len() - tree_nodes_len,
            active_removal_count: u32::try_from(active_removal_count)
                .expect("active removal count overflow"),
            active_add_node_count: u32::try_from(added_nodes_at_level)
                .expect("active add node count overflow"),
        });

        self.path.segments.push(segment);
    }

    fn pop_segment(&mut self) {
        let node_counter = self.active_node_counter.pop().unwrap();
        self.tree_nodes
            .truncate(self.tree_nodes.len() - node_counter.active_tree_count);
        self.total_active_add_nodes -= node_counter.active_add_node_count as usize;
        if node_counter.active_removal_count > 0 {
            self.active_removal_sets.truncate(
                self.active_removal_sets.len() - node_counter.active_removal_count as usize,
            );
            self.combined_exclusions_dirty = true;
        }
        if let Some(popped) = self.path.segments.pop()
            && self.add_implicit_index_wildcards
            && popped.is_index()
        {
            self.wildcard_segment_depth -= 1;
        }
    }

    fn visit_string<'s>(
        &'s mut self,
        value: &str,
    ) -> Result<VisitStringResult<'s, 'path>, ScannerError> {
        let excluded_words: &[u64] = match self.active_removal_sets.as_slice() {
            [] => &[],
            [single] => single.as_slice(),
            multiple => {
                if self.combined_exclusions_dirty {
                    self.combined_exclusions.set_union_of(multiple);
                    self.combined_exclusions_dirty = false;
                }
                self.combined_exclusions.as_slice()
            }
        };

        // Without an active wildcard index on the path, `tree_nodes` forms a single ancestor chain
        // already deduplicated by `RuleTree`; with <=1 node holding `added_rules`, duplicates are
        // also impossible because each node's `added_rules` is deduplicated on insert.
        let needs_dedup = self.wildcard_segment_depth > 0 && self.total_active_add_nodes > 1;
        let used_rule_set = if needs_dedup {
            Some(
                self.bool_set
                    .get_or_insert_with(|| BoolSet::new(self.num_rules)),
            )
        } else {
            None
        };

        let will_mutate = self.content_visitor.visit_content(
            &self.path,
            value,
            RuleIndexVisitor {
                tree_nodes: self.tree_nodes.as_slice(),
                used_rule_set,
            },
            ExclusionCheck { excluded_words },
        );
        if needs_dedup && let Some(bool_set) = &mut self.bool_set {
            bool_set.reset();
        }
        will_mutate.map(|will_mutate| VisitStringResult {
            might_mutate: will_mutate,
            path: &self.path,
        })
    }
}

pub struct RuleIndexVisitor<'a> {
    tree_nodes: &'a [ActiveRuleTree<'a>],
    used_rule_set: Option<&'a mut BoolSet>,
}

impl RuleIndexVisitor<'_> {
    /// Visits all rules associated with the current string. This may
    /// potentially return no rule indices at all.
    pub fn visit_rule_indices(
        &mut self,
        mut visit: impl FnMut(usize) -> Result<(), ScannerError>,
    ) -> Result<(), ScannerError> {
        // visit rules with an `Include` scope
        if let Some(used_rule_set) = &mut self.used_rule_set {
            let used = used_rule_set.as_mut_slice();
            for include_node in self.tree_nodes {
                if include_node.index_wildcard_match {
                    // This is guaranteed to be a duplicated node. Skip it
                    continue;
                }
                for &rule_index in &include_node.rule_tree.added_rules {
                    let slot = &mut used[rule_index];
                    if !*slot {
                        *slot = true;
                        (visit)(rule_index)?;
                    }
                }
            }
        } else {
            for include_node in self.tree_nodes {
                if include_node.index_wildcard_match {
                    // This is guaranteed to be a duplicated node. Skip it
                    continue;
                }
                for &rule_index in &include_node.rule_tree.added_rules {
                    (visit)(rule_index)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct RuleTree {
    added_rules: Vec<usize>,
    // Bitset of rules excluded at this node; trailing zero words are trimmed so
    // `removed_rules.is_empty()` is exact for "no exclusions at this node".
    removed_rules: Vec<u64>,
    children: AHashMap<PathSegment<'static>, RuleTree>,
}

impl RuleTree {
    pub fn new() -> Self {
        Self {
            added_rules: vec![],
            removed_rules: vec![],
            children: AHashMap::new(),
        }
    }

    pub fn insert_rule_add(&mut self, path: &Path<'static>, rule_index: usize) {
        self.insert_rule_add_inner(&path.segments, rule_index);
    }

    pub fn insert_rule_removal(&mut self, path: &Path<'static>, rule_index: usize) {
        self.insert_rule_removal_inner(&path.segments, rule_index);
    }

    fn insert_rule_add_inner(&mut self, path: &[PathSegment<'static>], rule_index: usize) {
        if self.added_rules.contains(&rule_index) {
            return;
        }
        if let Some((first, remaining)) = path.split_first() {
            let child_tree = self
                .children
                .entry(first.clone())
                .or_insert_with(RuleTree::new);
            child_tree.insert_rule_add_inner(remaining, rule_index);
        } else {
            // remove any recursive children, since they will be duplicated
            self.recursively_remove_add(rule_index);
            self.added_rules.push(rule_index);
        }
    }

    fn insert_rule_removal_inner(&mut self, path: &[PathSegment<'static>], rule_index: usize) {
        if contains_bit(&self.removed_rules, rule_index) {
            return;
        }
        if let Some((first, remaining)) = path.split_first() {
            let child_tree = self
                .children
                .entry(first.clone())
                .or_insert_with(RuleTree::new);
            child_tree.insert_rule_removal_inner(remaining, rule_index);
        } else {
            // remove any recursive children, since they will be duplicated
            self.recursively_remove_exclusion(rule_index);
            set_bit(&mut self.removed_rules, rule_index);
        }
    }

    fn recursively_remove_add(&mut self, rule_index: usize) {
        self.added_rules.retain(|&x| x != rule_index);
        for child_tree in self.children.values_mut() {
            child_tree.recursively_remove_add(rule_index);
        }
    }

    fn recursively_remove_exclusion(&mut self, rule_index: usize) {
        clear_bit(&mut self.removed_rules, rule_index);
        for child_tree in self.children.values_mut() {
            child_tree.recursively_remove_exclusion(rule_index);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::simple_event::SimpleEvent;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
    struct VisitedPath {
        path: Path<'static>,
        content: String,
        rules: Vec<VisitedRule>,
    }

    #[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
    struct VisitedRule {
        rule_index: usize,
        is_excluded: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Visited {
        paths: Vec<VisitedPath>,
    }

    // Visits the event and returns the paths that were visited
    fn visit_event(event: &mut impl Event, ruleset: &ScopedRuleSet) -> Visited {
        let mut visited = Visited { paths: vec![] };

        struct RecordingContentVisitor<'a> {
            visited: &'a mut Visited,
        }

        impl<'a> ContentVisitor<'a> for RecordingContentVisitor<'a> {
            fn visit_content<'content_visitor>(
                &'content_visitor mut self,
                path: &Path<'a>,
                content: &str,
                mut rule_iter: RuleIndexVisitor,
                exclusion_check: ExclusionCheck<'content_visitor>,
            ) -> Result<bool, ScannerError> {
                let mut rules = vec![];
                rule_iter.visit_rule_indices(|rule_index| {
                    rules.push(VisitedRule {
                        rule_index,
                        is_excluded: exclusion_check.is_excluded(rule_index),
                    });
                    Ok(())
                })?;
                rules.sort();
                self.visited.paths.push(VisitedPath {
                    path: path.into_static(),
                    content: content.to_string(),
                    rules,
                });
                Ok(true)
            }
        }

        ruleset
            .visit_string_rule_combinations(
                event,
                RecordingContentVisitor {
                    visited: &mut visited,
                },
            )
            .unwrap();
        visited.paths.sort();
        visited
    }

    #[test]
    fn test_inclusive_scopes() {
        // Fields are scanned as long as they are a child of any `include` path
        let ruleset = ScopedRuleSet::new(&[
            Scope::include(vec![Path::from(vec!["a".into()])]),
            Scope::include(vec![Path::from(vec!["a".into(), "b".into()])]),
            Scope::include(vec![]),
        ]);

        let mut event = SimpleEvent::Map(
            [
                (
                    "a".into(),
                    SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("value-ab".into())),
                            ("c".into(), SimpleEvent::String("value-ac".into())),
                        ]
                        .into(),
                    ),
                ),
                ("d".into(), SimpleEvent::String("value-d".into())),
            ]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "b".into()]),
                        content: "value-ab".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: false
                            }
                        ]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "c".into()]),
                        content: "value-ac".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["d".into()]),
                        content: "value-d".into(),
                        rules: vec![]
                    }
                ],
            }
        );
    }

    #[test]
    fn test_inclusive_scopes_array() {
        // Fields are scanned as long as they are a child of any `include` path
        let ruleset = ScopedRuleSet::new(&[
            Scope::include(vec![Path::from(vec![0.into()])]),
            Scope::include(vec![Path::from(vec![1.into(), 0.into()])]),
            Scope::include(vec![Path::from(vec![2.into(), 0.into()])]),
        ]);

        let mut event = SimpleEvent::List(vec![
            SimpleEvent::String("value-0".into()),
            SimpleEvent::String("value-1".into()),
            SimpleEvent::List(vec![SimpleEvent::String("value-2-0".into())]),
            SimpleEvent::String("value-3".into()),
        ]);

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec![0.into()]),
                        content: "value-0".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec![1.into()]),
                        content: "value-1".into(),
                        rules: vec![]
                    },
                    VisitedPath {
                        path: Path::from(vec![2.into(), 0.into()]),
                        content: "value-2-0".into(),
                        rules: vec![VisitedRule {
                            rule_index: 2,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec![3.into()]),
                        content: "value-3".into(),
                        rules: vec![]
                    }
                ],
            }
        );
    }

    #[test]
    fn test_exclusive_scopes() {
        // All fields are scanned, but fields that are children of any `exclude` path are marked as excluded
        let ruleset = ScopedRuleSet::new(&[
            Scope::exclude(vec![Path::from(vec!["a".into()])]),
            Scope::exclude(vec![Path::from(vec!["a".into(), "b".into()])]),
            // matches everything (it will always be excluded)
            Scope::all(),
        ]);

        let mut event = SimpleEvent::Map(
            [
                (
                    "a".into(),
                    SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("value-ab".into())),
                            ("c".into(), SimpleEvent::String("value-ac".into())),
                        ]
                        .into(),
                    ),
                ),
                ("d".into(), SimpleEvent::String("value-d".into())),
                ("e".into(), SimpleEvent::List(vec![])),
            ]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "b".into()]),
                        content: "value-ab".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: true
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: true
                            },
                            VisitedRule {
                                rule_index: 2,
                                is_excluded: false
                            }
                        ]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "c".into()]),
                        content: "value-ac".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: true
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 2,
                                is_excluded: false
                            }
                        ]
                    },
                    VisitedPath {
                        path: Path::from(vec!["d".into()]),
                        content: "value-d".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 2,
                                is_excluded: false
                            }
                        ]
                    }
                ],
            },
        );
    }

    #[test]
    fn test_exclusive_scopes_array() {
        // All fields are scanned, but fields that are children of any `exclude` path are marked as excluded
        let ruleset = ScopedRuleSet::new(&[
            Scope::exclude(vec![Path::from(vec![0.into()])]),
            Scope::exclude(vec![Path::from(vec![1.into(), 0.into()])]),
            Scope::exclude(vec![Path::from(vec![2.into(), 0.into()])]),
        ]);

        let mut event = SimpleEvent::List(vec![
            SimpleEvent::String("value-0".into()),
            SimpleEvent::String("value-1".into()),
            SimpleEvent::List(vec![SimpleEvent::String("value-2-0".into())]),
            SimpleEvent::String("value-3".into()),
        ]);

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec![0.into()]),
                        content: "value-0".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: true
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 2,
                                is_excluded: false
                            }
                        ]
                    },
                    VisitedPath {
                        path: Path::from(vec![1.into()]),
                        content: "value-1".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 2,
                                is_excluded: false
                            }
                        ]
                    },
                    VisitedPath {
                        path: Path::from(vec![2.into(), 0.into()]),
                        content: "value-2-0".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 2,
                                is_excluded: true
                            }
                        ]
                    },
                    VisitedPath {
                        path: Path::from(vec![3.into()]),
                        content: "value-3".into(),
                        rules: vec![
                            VisitedRule {
                                rule_index: 0,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 1,
                                is_excluded: false
                            },
                            VisitedRule {
                                rule_index: 2,
                                is_excluded: false
                            }
                        ]
                    }
                ],
            }
        );
    }

    #[test]
    fn test_include_and_exclude() {
        // Fields that are children of any `include` path are scanned, but they are only marked as
        // excluded if they are children of any `exclude` path
        let ruleset = ScopedRuleSet::new(&[Scope::include_and_exclude(
            vec![Path::from(vec![2.into()])],
            vec![Path::from(vec![2.into(), 0.into()])],
        )]);

        let mut event = SimpleEvent::List(vec![
            SimpleEvent::String("value-0".into()),
            SimpleEvent::String("value-1".into()),
            SimpleEvent::List(vec![
                SimpleEvent::String("value-2-0".into()),
                SimpleEvent::String("value-2-1".into()),
            ]),
            SimpleEvent::String("value-3".into()),
        ]);

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec![0.into()]),
                        content: "value-0".into(),
                        rules: vec![]
                    },
                    VisitedPath {
                        path: Path::from(vec![1.into()]),
                        content: "value-1".into(),
                        rules: vec![]
                    },
                    VisitedPath {
                        path: Path::from(vec![2.into(), 0.into()]),
                        content: "value-2-0".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: true
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec![2.into(), 1.into()]),
                        content: "value-2-1".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec![3.into()]),
                        content: "value-3".into(),
                        rules: vec![]
                    },
                ]
            }
        );
    }

    #[test]
    fn test_include_and_exclude_priority() {
        // exclude paths have priority, and override any include path. (even if the include is more specific)

        let ruleset = ScopedRuleSet::new(&[Scope::include_and_exclude(
            // This include is ignored, since an exclude overrides it
            vec![Path::from(vec![1.into(), 0.into()])],
            vec![Path::from(vec![1.into()])],
        )]);

        let mut event = SimpleEvent::List(vec![
            SimpleEvent::String("value-0".into()),
            SimpleEvent::List(vec![
                SimpleEvent::String("value-1-0".into()),
                SimpleEvent::String("value-1-1".into()),
            ]),
        ]);

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec![0.into()]),
                        content: "value-0".into(),
                        rules: vec![]
                    },
                    VisitedPath {
                        path: Path::from(vec![1.into(), 0.into()]),
                        content: "value-1-0".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: true
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec![1.into(), 1.into()]),
                        content: "value-1-1".into(),
                        rules: vec![]
                    }
                ],
            }
        );
    }

    fn visited_path(path: Path<'static>, content: &str, rules: &[(usize, bool)]) -> VisitedPath {
        VisitedPath {
            path,
            content: content.into(),
            rules: rules
                .iter()
                .map(|&(rule_index, is_excluded)| VisitedRule {
                    rule_index,
                    is_excluded,
                })
                .collect(),
        }
    }

    fn event_with_fields_a_and_b_c() -> SimpleEvent {
        SimpleEvent::Map(
            [
                ("a".into(), SimpleEvent::String("value-a".into())),
                (
                    "b".into(),
                    SimpleEvent::Map(
                        [("c".into(), SimpleEvent::String("value-b-c".into()))].into(),
                    ),
                ),
            ]
            .into(),
        )
    }

    #[test]
    fn test_exclude_root_marks_every_field_excluded() {
        let ruleset = ScopedRuleSet::new(&[Scope::exclude(vec![Path::root()])]);

        let paths = visit_event(&mut event_with_fields_a_and_b_c(), &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    visited_path(Path::from(vec!["a".into()]), "value-a", &[(0, true)]),
                    visited_path(
                        Path::from(vec!["b".into(), "c".into()]),
                        "value-b-c",
                        &[(0, true)]
                    ),
                ],
            }
        );
    }

    #[test]
    fn test_include_and_exclude_same_path_marks_it_excluded() {
        let a = Path::from(vec!["a".into()]);
        let ruleset =
            ScopedRuleSet::new(&[Scope::include_and_exclude(vec![a.clone()], vec![a.clone()])]);

        let paths = visit_event(&mut event_with_fields_a_and_b_c(), &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    visited_path(a, "value-a", &[(0, true)]),
                    visited_path(Path::from(vec!["b".into(), "c".into()]), "value-b-c", &[]),
                ],
            }
        );
    }

    #[test]
    fn test_exclude_and_include_scopes_on_same_path_are_independent_per_rule() {
        let a = Path::from(vec!["a".into()]);
        let ruleset = ScopedRuleSet::new(&[
            Scope::exclude(vec![a.clone()]),
            Scope::include(vec![a.clone()]),
        ]);

        let paths = visit_event(&mut event_with_fields_a_and_b_c(), &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    visited_path(a, "value-a", &[(0, true), (1, false)]),
                    visited_path(
                        Path::from(vec!["b".into(), "c".into()]),
                        "value-b-c",
                        &[(0, false)]
                    ),
                ],
            }
        );
    }

    #[test]
    fn test_include_same_change_multiple_times() {
        // If multiple "include" scopes cover the same field, it should only be returned once.

        let ruleset = ScopedRuleSet::new(&[Scope::include(vec![
            Path::from(vec!["a".into()]),
            Path::from(vec!["a".into(), "b".into()]),
        ])]);

        let mut event = SimpleEvent::Map(
            [
                (
                    "a".into(),
                    SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("value-ab".into())),
                            ("c".into(), SimpleEvent::String("value-ac".into())),
                        ]
                        .into(),
                    ),
                ),
                ("d".into(), SimpleEvent::String("value-d".into())),
            ]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "b".into()]),
                        content: "value-ab".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "c".into()]),
                        content: "value-ac".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["d".into()]),
                        content: "value-d".into(),
                        rules: vec![]
                    }
                ],
            }
        );
    }

    #[test]
    fn test_include_root_multiple_times() {
        // This makes sure duplicate rule changes (at the root of the tree) are removed
        let ruleset =
            ScopedRuleSet::new(&[Scope::include(vec![Path::from(vec![]), Path::from(vec![])])]);

        let mut event = SimpleEvent::Map(
            [
                (
                    "a".into(),
                    SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("value-ab".into())),
                            ("c".into(), SimpleEvent::String("value-ac".into())),
                        ]
                        .into(),
                    ),
                ),
                ("d".into(), SimpleEvent::String("value-d".into())),
            ]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "b".into()]),
                        content: "value-ab".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "c".into()]),
                        content: "value-ac".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["d".into()]),
                        content: "value-d".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    }
                ],
            }
        );
    }

    #[test]
    fn test_include_same_change_multiple_times_reversed() {
        // If multiple "include" scopes cover the same field, it should only be returned once.
        // This one specifically tests when a more generic path is added _after_ a specific path.
        // (The more specific one should be removed from the tree)

        let ruleset = ScopedRuleSet::new(&[Scope::include(vec![
            Path::from(vec!["a".into(), "b".into()]),
            Path::from(vec!["a".into()]),
        ])]);

        let mut event = SimpleEvent::Map(
            [
                (
                    "a".into(),
                    SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("value-ab".into())),
                            ("c".into(), SimpleEvent::String("value-ac".into())),
                        ]
                        .into(),
                    ),
                ),
                ("d".into(), SimpleEvent::String("value-d".into())),
            ]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "b".into()]),
                        content: "value-ab".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), "c".into()]),
                        content: "value-ac".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["d".into()]),
                        content: "value-d".into(),
                        rules: vec![]
                    }
                ],
            }
        );
    }

    #[test]
    fn test_fields_should_act_as_wildcard_on_lists() {
        let ruleset = ScopedRuleSet::new(&[Scope::include(vec![Path::from(vec![
            "a".into(),
            "b".into(),
        ])])])
        .with_implicit_index_wildcards(true);

        let mut event = SimpleEvent::Map(
            [(
                "a".into(),
                SimpleEvent::List(vec![SimpleEvent::Map(
                    [("b".into(), SimpleEvent::String("value-a-0-b".to_string()))].into(),
                )]),
            )]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![VisitedPath {
                    path: Path::from(vec!["a".into(), 0.into(), "b".into()]),
                    content: "value-a-0-b".into(),
                    // Rule 0 matches this path even though there is a "0" index between the "a" and "b" field
                    rules: vec![VisitedRule {
                        rule_index: 0,
                        is_excluded: false
                    }]
                },],
            }
        );
    }

    #[test]
    fn test_exclude_implicit_wildcard_path() {
        // This makes sure that exclusions are applied even when a path matches due to an
        // implicit array wildcard.

        let ab_path = Path::from(vec!["a".into(), "b".into()]);
        let ruleset = ScopedRuleSet::new(&[Scope::include_and_exclude(
            vec![ab_path.clone()],
            vec![ab_path],
        )])
        .with_implicit_index_wildcards(true);

        let mut event = SimpleEvent::Map(
            [(
                "a".into(),
                SimpleEvent::List(vec![SimpleEvent::Map(
                    [("b".into(), SimpleEvent::String("value-a-0-b".to_string()))].into(),
                )]),
            )]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![VisitedPath {
                    path: Path::from(vec!["a".into(), 0.into(), "b".into()]),
                    content: "value-a-0-b".into(),
                    // Rule 0 matches this path even though there is a "0" index between the "a" and "b" field
                    rules: vec![VisitedRule {
                        rule_index: 0,
                        is_excluded: true
                    }]
                },],
            }
        );
    }

    #[test]
    fn test_included_scope_both_implicit_and_explicit_index() {
        let a_0_c_path = Path::from(vec!["a".into(), 0.into(), "c".into()]);
        let ab_path = Path::from(vec!["a".into(), "b".into()]);
        let a_1_d_path = Path::from(vec!["a".into(), 1.into(), "d".into()]);

        let ruleset = ScopedRuleSet::new(&[Scope::include(vec![a_0_c_path, ab_path, a_1_d_path])])
            .with_implicit_index_wildcards(true);

        let mut event = SimpleEvent::Map(
            [(
                "a".into(),
                SimpleEvent::List(vec![
                    SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("value-a-0-b".to_string())),
                            ("c".into(), SimpleEvent::String("value-a-0-c".to_string())),
                            ("d".into(), SimpleEvent::String("value-a-0-d".to_string())),
                        ]
                        .into(),
                    ),
                    SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("value-a-1-b".to_string())),
                            ("c".into(), SimpleEvent::String("value-a-1-c".to_string())),
                            ("d".into(), SimpleEvent::String("value-a-1-d".to_string())),
                        ]
                        .into(),
                    ),
                ]),
            )]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![
                    VisitedPath {
                        path: Path::from(vec!["a".into(), 0.into(), "b".into()]),
                        content: "value-a-0-b".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), 0.into(), "c".into()]),
                        content: "value-a-0-c".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), 0.into(), "d".into()]),
                        content: "value-a-0-d".into(),
                        rules: vec![]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), 1.into(), "b".into()]),
                        content: "value-a-1-b".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), 1.into(), "c".into()]),
                        content: "value-a-1-c".into(),
                        rules: vec![]
                    },
                    VisitedPath {
                        path: Path::from(vec!["a".into(), 1.into(), "d".into()]),
                        content: "value-a-1-d".into(),
                        rules: vec![VisitedRule {
                            rule_index: 0,
                            is_excluded: false
                        }]
                    },
                ],
            }
        );
    }

    #[test]
    fn test_duplicate_rules_are_filtered_out() {
        // Internally there may be multiple "active" trees which could end up storing duplicate rules.
        // Those duplicates must be filtered out.

        // Both of these scopes match the path "a[0].b" (one with an explicit index, one with an implicit wildcard index)
        let a_b_path = Path::from(vec!["a".into(), "b".into()]);
        let a_0_b_path = Path::from(vec!["a".into(), 0.into(), "b".into()]);

        let ruleset = ScopedRuleSet::new(&[Scope::include(vec![a_b_path, a_0_b_path])])
            .with_implicit_index_wildcards(true);

        let mut event = SimpleEvent::Map(
            [(
                "a".into(),
                SimpleEvent::List(vec![SimpleEvent::Map(
                    [("b".into(), SimpleEvent::String("value-a-0-b".to_string()))].into(),
                )]),
            )]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![VisitedPath {
                    path: Path::from(vec!["a".into(), 0.into(), "b".into()]),
                    content: "value-a-0-b".into(),
                    rules: vec![VisitedRule {
                        rule_index: 0,
                        is_excluded: false
                    }]
                },],
            }
        );
    }

    #[test]
    fn test_deeply_nested_implicit_wildcard_index() {
        // A wildcard index can skip multiple levels of indexing, not just 1

        let a_b_path = Path::from(vec!["a".into(), "b".into()]);
        let ruleset = ScopedRuleSet::new(&[Scope::include(vec![a_b_path])])
            .with_implicit_index_wildcards(true);

        let mut event = SimpleEvent::Map(
            [(
                "a".into(),
                SimpleEvent::List(vec![SimpleEvent::List(vec![SimpleEvent::Map(
                    [("b".into(), SimpleEvent::String("value-a-0-0-b".to_string()))].into(),
                )])]),
            )]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![VisitedPath {
                    path: Path::from(vec!["a".into(), 0.into(), 0.into(), "b".into()]),
                    content: "value-a-0-0-b".into(),
                    rules: vec![VisitedRule {
                        rule_index: 0,
                        is_excluded: false
                    }]
                },],
            }
        );
    }

    #[test]
    fn test_implicit_index_wildcard_is_disabled_by_default() {
        let ruleset = ScopedRuleSet::new(&[Scope::include(vec![Path::from(vec![
            "a".into(),
            "b".into(),
        ])])]);

        let mut event = SimpleEvent::Map(
            [(
                "a".into(),
                SimpleEvent::List(vec![SimpleEvent::Map(
                    [("b".into(), SimpleEvent::String("value-a-0-b".to_string()))].into(),
                )]),
            )]
            .into(),
        );

        let paths = visit_event(&mut event, &ruleset);

        assert_eq!(
            paths,
            Visited {
                paths: vec![VisitedPath {
                    path: Path::from(vec!["a".into(), 0.into(), "b".into()]),
                    content: "value-a-0-b".into(),
                    // Rule 0 does NOT match, since the implicit index wildcard is disabled
                    rules: vec![]
                },],
            }
        );
    }

    #[test]
    fn test_inline_stack_boundaries_and_differential() {
        let mut stack: InlineStack<usize, 16> = InlineStack::new();
        assert!(stack.is_empty());
        assert_eq!(stack.len(), 0);
        assert_eq!(stack.last(), None);
        assert_eq!(stack.pop(), None);
        assert!(stack.as_slice().is_empty());

        for i in 0..16 {
            stack.push(i);
        }
        assert!(matches!(stack, InlineStack::Inline { len: 16, .. }));
        assert_eq!(stack.len(), 16);
        assert_eq!(stack.last(), Some(&15));

        // 17th push triggers spill to Heap.
        stack.push(16);
        assert!(matches!(stack, InlineStack::Heap(_)));
        assert_eq!(stack.len(), 17);
        assert_eq!(stack.as_slice(), &(0..17).collect::<Vec<_>>()[..]);

        stack.truncate(10);
        assert_eq!(stack.len(), 10);
        assert_eq!(stack.last(), Some(&9));

        // Truncate above len is a no-op.
        stack.truncate(50);
        assert_eq!(stack.len(), 10);

        // Randomized differential test against Vec.
        let mut seed: u64 = 0xdead_beef_cafe_babe;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for _ in 0..100 {
            let mut s: InlineStack<u32, 4> = if next_u64() % 2 == 0 {
                InlineStack::new()
            } else {
                InlineStack::with_first(7)
            };
            let mut oracle: Vec<u32> = s.as_slice().to_vec();

            for _ in 0..60 {
                match next_u64() % 4 {
                    0 | 1 => {
                        let v = (next_u64() % 1000) as u32;
                        s.push(v);
                        oracle.push(v);
                    }
                    2 => {
                        assert_eq!(s.pop(), oracle.pop());
                    }
                    _ => {
                        let new_len = (next_u64() as usize) % (oracle.len() + 3);
                        s.truncate(new_len);
                        oracle.truncate(new_len);
                    }
                }
                assert_eq!(s.len(), oracle.len());
                assert_eq!(s.is_empty(), oracle.is_empty());
                assert_eq!(s.last(), oracle.last());
                assert_eq!(s.as_slice(), oracle.as_slice());
            }
        }
    }

    #[test]
    fn test_deep_nested_paths_spill_beyond_inline_stack_with_exclusions() {
        let depth = 25usize;
        let path_to_depth = |d: usize| -> Path<'static> {
            let mut segs = Vec::with_capacity(d);
            for i in 0..d {
                segs.push(PathSegment::Field(format!("k{i}").into()));
            }
            Path::from(segs)
        };

        let scopes = vec![
            // Rule 0: included everywhere, excluded at depth 3.
            Scope::exclude(vec![path_to_depth(3)]),
            // Rule 1: included everywhere, excluded at depth 18 (past INLINE_STACK_CAPACITY).
            Scope::exclude(vec![path_to_depth(18)]),
            // Rule 2: included only at depth 20, excluded at depth 22.
            Scope::include_and_exclude(vec![path_to_depth(20)], vec![path_to_depth(22)]),
        ];
        let ruleset = ScopedRuleSet::new(&scopes).with_implicit_index_wildcards(true);

        let mut event = SimpleEvent::String("deep-leaf".into());
        for i in (0..depth).rev() {
            let mut map = std::collections::BTreeMap::new();
            map.insert(format!("k{i}"), event);
            map.insert("sib".into(), SimpleEvent::String(format!("sib-{i}")));
            event = SimpleEvent::Map(map);
        }

        let visited = visit_event(&mut event, &ruleset);

        // Verify sibling at depth 0 (path "sib"): no rules excluded, rules 0 and 1 active.
        let sib0 = visited.paths.iter().find(|p| p.content == "sib-0").unwrap();
        assert_eq!(
            sib0.rules,
            vec![
                VisitedRule {
                    rule_index: 0,
                    is_excluded: false
                },
                VisitedRule {
                    rule_index: 1,
                    is_excluded: false
                },
            ]
        );

        // Sibling at depth 19 (path k0..k18.sib): rules 0 and 1 excluded, rule 2 not yet included.
        let sib19 = visited
            .paths
            .iter()
            .find(|p| p.content == "sib-19")
            .unwrap();
        assert_eq!(
            sib19.rules,
            vec![
                VisitedRule {
                    rule_index: 0,
                    is_excluded: true
                },
                VisitedRule {
                    rule_index: 1,
                    is_excluded: true
                },
            ]
        );

        // Sibling at depth 21 (path k0..k20.sib): rule 2 included and NOT excluded.
        let sib21 = visited
            .paths
            .iter()
            .find(|p| p.content == "sib-21")
            .unwrap();
        assert_eq!(
            sib21.rules,
            vec![
                VisitedRule {
                    rule_index: 0,
                    is_excluded: true
                },
                VisitedRule {
                    rule_index: 1,
                    is_excluded: true
                },
                VisitedRule {
                    rule_index: 2,
                    is_excluded: false
                },
            ]
        );

        // Deepest leaf at depth 25: all 3 rules active and all 3 excluded.
        let leaf = visited
            .paths
            .iter()
            .find(|p| p.content == "deep-leaf")
            .unwrap();
        assert_eq!(
            leaf.rules,
            vec![
                VisitedRule {
                    rule_index: 0,
                    is_excluded: true
                },
                VisitedRule {
                    rule_index: 1,
                    is_excluded: true
                },
                VisitedRule {
                    rule_index: 2,
                    is_excluded: true
                },
            ]
        );
    }

    #[test]
    fn test_many_rules_beyond_256_inline_bitset_boundary() {
        let num_rules = 300usize;
        let a = Path::from(vec!["a".into()]);
        let a_b = Path::from(vec!["a".into(), "b".into()]);
        let a_0_b = Path::from(vec!["a".into(), 0.into(), "b".into()]);

        let mut scopes = Vec::with_capacity(num_rules);
        for i in 0..num_rules {
            if i % 4 == 0 {
                // Specific then generic exclusion tests recursive exclusion clearing + trimming.
                scopes.push(Scope::exclude(vec![a_b.clone(), a.clone()]));
            } else if i % 4 == 1 {
                // Included via both explicit and implicit wildcard paths; excluded at a.b.
                scopes.push(Scope::include_and_exclude(
                    vec![a_b.clone(), a_0_b.clone()],
                    vec![a_b.clone()],
                ));
            } else if i % 4 == 2 {
                scopes.push(Scope::include(vec![a_b.clone(), a_0_b.clone()]));
            } else {
                scopes.push(Scope::all());
            }
        }

        let ruleset = ScopedRuleSet::new(&scopes).with_implicit_index_wildcards(true);
        let mut event = SimpleEvent::Map(
            [
                (
                    "a".into(),
                    SimpleEvent::List(vec![SimpleEvent::Map(
                        [
                            ("b".into(), SimpleEvent::String("v-ab".into())),
                            ("c".into(), SimpleEvent::String("v-ac".into())),
                        ]
                        .into(),
                    )]),
                ),
                ("other".into(), SimpleEvent::String("v-other".into())),
            ]
            .into(),
        );

        let visited = visit_event(&mut event, &ruleset);

        let ab = visited.paths.iter().find(|p| p.content == "v-ab").unwrap();
        assert_eq!(ab.rules.len(), num_rules);
        for (i, r) in ab.rules.iter().enumerate() {
            assert_eq!(r.rule_index, i);
            let expected_excluded = i % 4 == 0 || i % 4 == 1;
            assert_eq!(r.is_excluded, expected_excluded, "rule {i} at a[0].b");
        }

        let ac = visited.paths.iter().find(|p| p.content == "v-ac").unwrap();
        for r in &ac.rules {
            let expected_excluded = r.rule_index % 4 == 0;
            assert_eq!(
                r.is_excluded, expected_excluded,
                "rule {} at a[0].c",
                r.rule_index
            );
        }

        let other = visited
            .paths
            .iter()
            .find(|p| p.content == "v-other")
            .unwrap();
        for r in &other.rules {
            assert!(!r.is_excluded, "rule {} at other", r.rule_index);
        }
    }

    #[test]
    fn test_exclusion_union_dirty_cache_across_siblings_and_backtracking() {
        let scopes = vec![
            Scope::exclude(vec![Path::from(vec!["a".into()])]),
            Scope::exclude(vec![Path::from(vec!["a".into(), "b".into()])]),
            Scope::exclude(vec![Path::from(vec!["a".into(), "c".into()])]),
            Scope::exclude(vec![Path::from(vec![
                "a".into(),
                "b".into(),
                "deep".into(),
            ])]),
        ];
        let ruleset = ScopedRuleSet::new(&scopes);

        let mut event = SimpleEvent::Map(
            [(
                "a".into(),
                SimpleEvent::Map(
                    [
                        (
                            "b".into(),
                            SimpleEvent::Map(
                                [
                                    ("s1".into(), SimpleEvent::String("ab-s1".into())),
                                    ("s2".into(), SimpleEvent::String("ab-s2".into())),
                                    ("deep".into(), SimpleEvent::String("ab-deep".into())),
                                ]
                                .into(),
                            ),
                        ),
                        (
                            "c".into(),
                            SimpleEvent::Map(
                                [("s1".into(), SimpleEvent::String("ac-s1".into()))].into(),
                            ),
                        ),
                        ("d".into(), SimpleEvent::String("ad".into())),
                    ]
                    .into(),
                ),
            )]
            .into(),
        );

        let visited = visit_event(&mut event, &ruleset);
        let check = |content: &str, expected: &[(usize, bool)]| {
            let vp = visited.paths.iter().find(|p| p.content == content).unwrap();
            let actual: Vec<(usize, bool)> = vp
                .rules
                .iter()
                .map(|r| (r.rule_index, r.is_excluded))
                .collect();
            assert_eq!(actual, expected, "mismatch for {content}");
        };

        check("ab-s1", &[(0, true), (1, true), (2, false), (3, false)]);
        check("ab-s2", &[(0, true), (1, true), (2, false), (3, false)]);
        check("ab-deep", &[(0, true), (1, true), (2, false), (3, true)]);
        check("ac-s1", &[(0, true), (1, false), (2, true), (3, false)]);
        check("ad", &[(0, true), (1, false), (2, false), (3, false)]);
    }

    fn path_matches_scope_prefix(
        event_path: &[PathSegment<'_>],
        scope_path: &[PathSegment<'_>],
        implicit_wildcards: bool,
    ) -> bool {
        fn rec(
            ev: &[PathSegment<'_>],
            sc: &[PathSegment<'_>],
            implicit_wildcards: bool,
            prev_was_wildcard: bool,
        ) -> bool {
            if sc.is_empty() {
                return true;
            }
            let Some((e_first, e_rest)) = ev.split_first() else {
                return false;
            };
            if (!prev_was_wildcard || !e_first.is_index())
                && *e_first == sc[0]
                && rec(e_rest, &sc[1..], implicit_wildcards, false)
            {
                return true;
            }
            if implicit_wildcards && e_first.is_index() && rec(e_rest, sc, implicit_wildcards, true)
            {
                return true;
            }
            false
        }
        rec(event_path, scope_path, implicit_wildcards, false)
    }

    #[test]
    fn test_scoped_ruleset_differential_vs_reference_oracle() {
        let mut seed: u64 = 0x5555_aaaa_3333_cccc;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let fields = ["a", "b", "c"];
        let rand_path = |max_len: usize, rng: &mut dyn FnMut() -> u64| -> Path<'static> {
            let len = (rng() as usize) % (max_len + 1);
            let mut segs = Vec::with_capacity(len);
            for _ in 0..len {
                if rng().is_multiple_of(4) {
                    segs.push(PathSegment::Index((rng() % 2) as usize));
                } else {
                    segs.push(PathSegment::Field(
                        fields[(rng() % fields.len() as u64) as usize].into(),
                    ));
                }
            }
            Path::from(segs)
        };

        for &implicit_wildcards in &[false, true] {
            for &num_rules in &[0usize, 8, 70, 270] {
                let mut scopes = Vec::with_capacity(num_rules);
                for _ in 0..num_rules {
                    let incl_mode = next_u64() % 3;
                    let excl_count = (next_u64() % 3) as usize;
                    let excludes: Vec<Path<'static>> = (0..excl_count)
                        .map(|_| rand_path(4, &mut next_u64))
                        .collect();
                    let scope = match incl_mode {
                        0 => Scope::exclude(excludes),
                        1 => {
                            let incl_count = (next_u64() % 3) as usize;
                            let includes = (0..incl_count)
                                .map(|_| rand_path(4, &mut next_u64))
                                .collect();
                            Scope::include_and_exclude(includes, excludes)
                        }
                        _ => Scope::all(),
                    };
                    scopes.push(scope);
                }

                let ruleset =
                    ScopedRuleSet::new(&scopes).with_implicit_index_wildcards(implicit_wildcards);

                let mut event = SimpleEvent::Map(
                    [
                        (
                            "a".into(),
                            SimpleEvent::List(vec![
                                SimpleEvent::Map(
                                    [
                                        ("b".into(), SimpleEvent::String("a0b".into())),
                                        (
                                            "c".into(),
                                            SimpleEvent::List(vec![SimpleEvent::Map(
                                                [("a".into(), SimpleEvent::String("a0c0a".into()))]
                                                    .into(),
                                            )]),
                                        ),
                                    ]
                                    .into(),
                                ),
                                SimpleEvent::String("a1".into()),
                            ]),
                        ),
                        (
                            "b".into(),
                            SimpleEvent::Map(
                                [("c".into(), SimpleEvent::String("bc".into()))].into(),
                            ),
                        ),
                    ]
                    .into(),
                );

                let visited = visit_event(&mut event, &ruleset);

                for vp in &visited.paths {
                    let mut expected_rules = Vec::new();
                    for (rule_index, scope) in scopes.iter().enumerate() {
                        let included = match &scope.include {
                            ScanArea::Everything => true,
                            ScanArea::Only(paths) => paths.iter().any(|p| {
                                path_matches_scope_prefix(
                                    &vp.path.segments,
                                    &p.segments,
                                    implicit_wildcards,
                                )
                            }),
                        };
                        if included {
                            let is_excluded = scope.exclude.iter().any(|p| {
                                path_matches_scope_prefix(
                                    &vp.path.segments,
                                    &p.segments,
                                    implicit_wildcards,
                                )
                            });
                            expected_rules.push(VisitedRule {
                                rule_index,
                                is_excluded,
                            });
                        }
                    }
                    assert_eq!(
                        vp.rules, expected_rules,
                        "mismatch for path={} wildcards={implicit_wildcards} num_rules={num_rules}",
                        vp.path
                    );
                }
            }
        }
    }

    /// Verbatim `origin/main` `ScopedRuleSet` implementation used as the end-to-end differential
    /// oracle for `push_segment`, `pop_segment`, `active_node_counter`, `InlineBitBuffer`, and
    /// lazy `BoolSet` deduplication.
    mod main_reference {
        use crate::event::{EventVisitor, VisitStringResult};
        use crate::scanner::scope::{ScanArea, Scope};
        use crate::{Event, Path, PathSegment, ScannerError};
        use ahash::AHashMap;

        struct MainBoolSet {
            rule_used: Vec<bool>,
        }

        impl MainBoolSet {
            fn new(num_rules: usize) -> Self {
                Self {
                    rule_used: vec![false; num_rules],
                }
            }

            fn get_and_set(&mut self, index: usize) -> bool {
                let result = self.rule_used[index];
                self.rule_used[index] = true;
                result
            }

            fn reset(&mut self) {
                self.rule_used.fill(false);
            }
        }

        pub(super) struct MainScopedRuleSet {
            tree: RuleTree,
            num_rules: usize,
            add_implicit_index_wildcards: bool,
        }

        impl MainScopedRuleSet {
            pub(super) fn new(rules_scopes: &[Scope]) -> Self {
                let mut tree = RuleTree::new();

                for (rule_index, scope) in rules_scopes.iter().enumerate() {
                    match &scope.include {
                        ScanArea::Everything => tree.insert_rule_add(&Path::root(), rule_index),
                        ScanArea::Only(paths) => {
                            for path in paths {
                                tree.insert_rule_add(path, rule_index);
                            }
                        }
                    }
                    for path in &scope.exclude {
                        tree.insert_rule_removal(path, rule_index);
                    }
                }
                Self {
                    tree,
                    num_rules: rules_scopes.len(),
                    add_implicit_index_wildcards: false,
                }
            }

            pub(super) fn with_implicit_index_wildcards(mut self, value: bool) -> Self {
                self.add_implicit_index_wildcards = value;
                self
            }

            pub(super) fn visit_all(
                &self,
                event: &mut impl Event,
            ) -> Vec<(Path<'static>, String, Vec<(usize, bool)>)> {
                let bool_set = if self.add_implicit_index_wildcards {
                    Some(MainBoolSet::new(self.num_rules))
                } else {
                    None
                };
                let mut out = Vec::new();
                let mut visitor = MainVisitor {
                    out: &mut out,
                    tree_nodes: vec![ActiveRuleTree {
                        rule_tree: &self.tree,
                        index_wildcard_match: false,
                    }],
                    active_node_counter: vec![NodeCounter {
                        active_tree_count: 1,
                    }],
                    path: Path::root(),
                    bool_set,
                    add_implicit_index_wildcards: self.add_implicit_index_wildcards,
                };
                event.visit_event(&mut visitor).unwrap();
                out
            }
        }

        struct ActiveRuleTree<'a> {
            rule_tree: &'a RuleTree,
            index_wildcard_match: bool,
        }

        struct NodeCounter {
            active_tree_count: usize,
        }

        struct MainVisitor<'a> {
            out: &'a mut Vec<(Path<'static>, String, Vec<(usize, bool)>)>,
            tree_nodes: Vec<ActiveRuleTree<'a>>,
            active_node_counter: Vec<NodeCounter>,
            path: Path<'a>,
            bool_set: Option<MainBoolSet>,
            add_implicit_index_wildcards: bool,
        }

        impl<'path> EventVisitor<'path> for MainVisitor<'path> {
            fn push_segment(&mut self, segment: PathSegment<'path>) {
                let num_active_trees = self.active_node_counter.last().unwrap().active_tree_count;
                let tree_nodes_len = self.tree_nodes.len();
                let active_trees_range = tree_nodes_len - num_active_trees..tree_nodes_len;

                for tree_index in active_trees_range {
                    if (!self.tree_nodes[tree_index].index_wildcard_match || !segment.is_index())
                        && let Some(child) =
                            self.tree_nodes[tree_index].rule_tree.children.get(&segment)
                    {
                        self.tree_nodes.push(ActiveRuleTree {
                            rule_tree: child,
                            index_wildcard_match: false,
                        });
                    }

                    if self.add_implicit_index_wildcards && segment.is_index() {
                        self.tree_nodes.push(ActiveRuleTree {
                            rule_tree: self.tree_nodes[tree_index].rule_tree,
                            index_wildcard_match: true,
                        });
                    }
                }

                self.active_node_counter.push(NodeCounter {
                    active_tree_count: self.tree_nodes.len() - tree_nodes_len,
                });
                self.path.segments.push(segment);
            }

            fn pop_segment(&mut self) {
                let node_counter = self.active_node_counter.pop().unwrap();
                for _ in 0..node_counter.active_tree_count {
                    let _popped = self.tree_nodes.pop();
                }
                self.path.segments.pop();
            }

            fn visit_string<'s>(
                &'s mut self,
                value: &str,
            ) -> Result<VisitStringResult<'s, 'path>, ScannerError> {
                let mut rules = Vec::new();
                for include_node in &self.tree_nodes {
                    if include_node.index_wildcard_match {
                        continue;
                    }
                    for change in &include_node.rule_tree.rule_changes {
                        if let RuleChange::Add(rule_index) = change {
                            let emit = if let Some(used_rule_set) = &mut self.bool_set {
                                !used_rule_set.get_and_set(*rule_index)
                            } else {
                                true
                            };
                            if emit {
                                let is_excluded = self.tree_nodes.iter().any(|n| {
                                    n.rule_tree
                                        .rule_changes
                                        .contains(&RuleChange::Remove(*rule_index))
                                });
                                rules.push((*rule_index, is_excluded));
                            }
                        }
                    }
                }
                if let Some(bool_set) = &mut self.bool_set {
                    bool_set.reset();
                }
                self.out
                    .push((self.path.into_static(), value.to_string(), rules));
                Ok(VisitStringResult {
                    might_mutate: false,
                    path: &self.path,
                })
            }
        }

        #[derive(Clone, Copy, PartialEq, Debug)]
        enum RuleChange {
            Add(usize),
            Remove(usize),
        }

        #[derive(Clone, Debug)]
        struct RuleTree {
            rule_changes: Vec<RuleChange>,
            children: AHashMap<PathSegment<'static>, RuleTree>,
        }

        impl RuleTree {
            fn new() -> Self {
                Self {
                    rule_changes: vec![],
                    children: AHashMap::new(),
                }
            }

            fn insert_rule_add(&mut self, path: &Path<'static>, rule_index: usize) {
                self.insert_rule_inner(&path.segments, RuleChange::Add(rule_index));
            }

            fn insert_rule_removal(&mut self, path: &Path<'static>, rule_index: usize) {
                self.insert_rule_inner(&path.segments, RuleChange::Remove(rule_index));
            }

            fn insert_rule_inner(
                &mut self,
                path: &[PathSegment<'static>],
                rule_change: RuleChange,
            ) {
                if self.rule_changes.contains(&rule_change) {
                    return;
                }
                if let Some((first, remaining)) = path.split_first() {
                    let child_tree = self
                        .children
                        .entry(first.clone())
                        .or_insert_with(RuleTree::new);
                    child_tree.insert_rule_inner(remaining, rule_change);
                } else {
                    self.recursively_remove(rule_change);
                    self.rule_changes.push(rule_change);
                }
            }

            fn recursively_remove(&mut self, rule_change: RuleChange) {
                self.rule_changes.retain(|x| *x != rule_change);
                for child_tree in self.children.values_mut() {
                    child_tree.recursively_remove(rule_change);
                }
            }
        }
    }

    fn visit_event_exact_order(
        event: &mut impl Event,
        ruleset: &ScopedRuleSet,
    ) -> Vec<(Path<'static>, String, Vec<(usize, bool)>)> {
        let mut out = Vec::new();

        struct ExactOrderVisitor<'a> {
            out: &'a mut Vec<(Path<'static>, String, Vec<(usize, bool)>)>,
        }

        impl<'a> ContentVisitor<'a> for ExactOrderVisitor<'a> {
            fn visit_content<'content_visitor>(
                &'content_visitor mut self,
                path: &Path<'a>,
                content: &str,
                mut rule_iter: RuleIndexVisitor,
                exclusion_check: ExclusionCheck<'content_visitor>,
            ) -> Result<bool, ScannerError> {
                let mut rules = Vec::new();
                rule_iter.visit_rule_indices(|rule_index| {
                    rules.push((rule_index, exclusion_check.is_excluded(rule_index)));
                    Ok(())
                })?;
                self.out
                    .push((path.into_static(), content.to_string(), rules));
                Ok(false)
            }
        }

        ruleset
            .visit_string_rule_combinations(event, ExactOrderVisitor { out: &mut out })
            .unwrap();
        out
    }

    fn build_random_event(
        rng: &mut dyn FnMut() -> u64,
        depth: usize,
        max_depth: usize,
        fields: &[&str],
    ) -> SimpleEvent {
        if depth >= max_depth || rng().is_multiple_of(5) {
            return SimpleEvent::String(format!("v{}_{}", depth, rng() % 100));
        }
        if rng().is_multiple_of(3) {
            let len = 1 + (rng() as usize) % 2;
            let items = (0..len)
                .map(|_| build_random_event(rng, depth + 1, max_depth, fields))
                .collect();
            SimpleEvent::List(items)
        } else {
            let len = 1 + (rng() as usize) % 2;
            let mut map = std::collections::BTreeMap::new();
            for _ in 0..len {
                let key = fields[(rng() as usize) % fields.len()].to_string();
                map.insert(key, build_random_event(rng, depth + 1, max_depth, fields));
            }
            SimpleEvent::Map(map)
        }
    }

    #[test]
    fn test_scoped_ruleset_differential_vs_verbatim_main_100k_evals() {
        let mut seed: u64 = 0x2026_1123_cafe_feed;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let fields = ["a", "b", "c", "d"];
        let rand_path = |max_len: usize, rng: &mut dyn FnMut() -> u64| -> Path<'static> {
            let len = (rng() as usize) % (max_len + 1);
            let mut segs = Vec::with_capacity(len);
            for _ in 0..len {
                if rng().is_multiple_of(3) {
                    segs.push(PathSegment::Index((rng() % 2) as usize));
                } else {
                    segs.push(PathSegment::Field(
                        fields[(rng() as usize) % fields.len()].into(),
                    ));
                }
            }
            Path::from(segs)
        };

        let rule_counts = [0usize, 1, 2, 16, 64, 128, 129, 256, 257, 300];
        let mut total_rule_evals = 0usize;
        let mut trial = 0usize;

        while total_rule_evals < 120_000 {
            let implicit_wildcards = trial % 2 == 1;
            let num_rules = rule_counts[trial % rule_counts.len()];
            // Periodically build deep paths (depth 20) to force InlineStack 16->17 spill across
            // tree_nodes, active_node_counter, and active_removal_sets.
            let deep_mode = trial % 7 == 0;
            let max_depth = if deep_mode { 20 } else { 5 };

            let mut scopes = Vec::with_capacity(num_rules);
            for _ in 0..num_rules {
                let excl_count = (next_u64() % 4) as usize;
                let excludes: Vec<Path<'static>> = (0..excl_count)
                    .map(|_| rand_path(if deep_mode { 20 } else { 5 }, &mut next_u64))
                    .collect();
                let scope = match next_u64() % 4 {
                    0 => Scope::exclude(excludes),
                    1 | 2 => {
                        let incl_count = (next_u64() % 4) as usize;
                        let includes = (0..incl_count)
                            .map(|_| rand_path(if deep_mode { 20 } else { 5 }, &mut next_u64))
                            .collect();
                        Scope::include_and_exclude(includes, excludes)
                    }
                    _ => Scope::all(),
                };
                scopes.push(scope);
            }

            let actual_rs =
                ScopedRuleSet::new(&scopes).with_implicit_index_wildcards(implicit_wildcards);
            let main_rs = main_reference::MainScopedRuleSet::new(&scopes)
                .with_implicit_index_wildcards(implicit_wildcards);

            let mut event = if deep_mode {
                let mut cur = SimpleEvent::String("deep-leaf".into());
                for d in (0..20).rev() {
                    if d % 5 == 0 {
                        cur = SimpleEvent::List(vec![cur, SimpleEvent::String(format!("li-{d}"))]);
                    } else {
                        let mut m = std::collections::BTreeMap::new();
                        m.insert(fields[d % fields.len()].to_string(), cur);
                        m.insert("sib".to_string(), SimpleEvent::String(format!("s-{d}")));
                        cur = SimpleEvent::Map(m);
                    }
                }
                cur
            } else {
                build_random_event(&mut next_u64, 0, max_depth, &fields)
            };

            let actual = visit_event_exact_order(&mut event, &actual_rs);
            let expected = main_rs.visit_all(&mut event);

            assert_eq!(
                actual, expected,
                "exact-order mismatch on trial={trial} wildcards={implicit_wildcards} num_rules={num_rules} deep={deep_mode}"
            );

            for (_, _, rules) in &actual {
                total_rule_evals += rules.len().max(1);
            }
            trial += 1;
        }
    }
}
