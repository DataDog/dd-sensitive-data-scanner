mod bool_set;

use crate::event::{EventVisitor, VisitStringResult};
use crate::proximity_keywords::UNIFIED_LINK_CHAR;
use crate::scanner::scope::Scope;
use crate::scoped_ruleset::bool_set::BoolSet;
use crate::{Event, Path, PathSegment};
use ahash::AHashMap;
use std::borrow::Cow;

/// A `ScopedRuleSet` determines which rules will be used to scan each field of an event, and which
/// paths are considered `excluded`.
#[derive(Debug)]
pub struct ScopedRuleSet {
    tree: RuleTree,
    // The number of rules stored in this set
    num_rules: usize,
    add_implicit_index_wildcards: bool,
    should_keywords_match_event_paths: bool,
}

impl ScopedRuleSet {
    /// The scopes for each rule. The indices of the scopes MUST match the rule index.
    pub fn new(rules_scopes: &[Scope]) -> Self {
        let mut tree = RuleTree::new();

        for (rule_index, scope) in rules_scopes.iter().enumerate() {
            match scope {
                Scope::Include { include, exclude } => {
                    for path in exclude {
                        tree.insert_rule_removal(path, rule_index);
                    }

                    for path in include {
                        tree.insert_rule_add(path, rule_index);
                    }
                }
                Scope::Exclude(paths) => {
                    tree.insert_rule_add(&Path::root(), rule_index);
                    for path in paths {
                        tree.insert_rule_removal(path, rule_index);
                    }
                }
            }
        }
        Self {
            tree,
            num_rules: rules_scopes.len(),
            add_implicit_index_wildcards: false,
            should_keywords_match_event_paths: false,
        }
    }

    pub fn with_implicit_index_wildcards(mut self, value: bool) -> Self {
        self.add_implicit_index_wildcards = value;
        self
    }

    pub fn with_keywords_should_match_event_paths(mut self, value: bool) -> Self {
        self.should_keywords_match_event_paths = value;
        self
    }

    pub fn visit_string_rule_combinations<'path, 'c: 'path>(
        &'c self,
        event: &'path mut impl Event,
        content_visitor: impl ContentVisitor<'path>,
    ) {
        let bool_set = if self.add_implicit_index_wildcards {
            Some(BoolSet::new(self.num_rules))
        } else {
            None
        };
        let mut visitor = ScopedRuledSetEventVisitor {
            content_visitor,
            tree_nodes: vec![ActiveRuleTree {
                rule_tree: &self.tree,
                index_wildcard_match: false,
            }],
            true_positive_rule_idx: vec![],
            sanitized_segments_until_node: vec![],
            active_node_counter: vec![NodeCounter {
                active_tree_count: 1,
                true_positive_rules_count: 0,
            }],
            path: Path::root(),
            bool_set,
            add_implicit_index_wildcards: self.add_implicit_index_wildcards,
            // should_keywords_match_event_paths: self.should_keywords_match_event_paths,
        };

        event.visit_event(&mut visitor)
    }
}

pub struct ExclusionCheck<'a> {
    tree_nodes: &'a [ActiveRuleTree<'a>],
}

impl<'a> ExclusionCheck<'a> {
    pub fn is_excluded(&self, rule_index: usize) -> bool {
        for include_node in self.tree_nodes {
            for change in &include_node.rule_tree.rule_changes {
                match change {
                    RuleChange::Add(_) => { /* ignore */ }
                    RuleChange::Remove(i) => {
                        if *i == rule_index {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

pub trait ContentVisitor<'path> {
    fn visit_content<'content_visitor>(
        &'content_visitor mut self,
        path: &Path<'path>,
        content: &str,
        rules: RuleIndexVisitor,
        is_excluded: ExclusionCheck<'content_visitor>,
        true_positive_rule_idx: &[usize],
    ) -> bool;

    fn find_true_positive_rules_from_current_path(
        &self,
        sanitized_path: &str,
        current_true_positive_rule_idx: &mut Vec<usize>,
    ) -> usize;
}

// This is just a reference to a RuleTree with some additional information
struct ActiveRuleTree<'a> {
    rule_tree: &'a RuleTree,
    // If this tree was pushed because of a wildcard index, indices aren't
    // allowed to match immediately after, so they are ignored.
    index_wildcard_match: bool,
}

struct NodeCounter {
    // This counts how many trees are currently active, which can
    // happen due to (implicit) wildcard segments. The last value in this
    // list is the current number of active trees (n), which is the last
    // n trees in `tree_nodes`.
    active_tree_count: usize,
    #[allow(dead_code)]
    // This counts how many rule indices we have pushed at the given node.
    // This helps remove the right number of elements when popping the segment.
    true_positive_rules_count: usize,
}

struct ScopedRuledSetEventVisitor<'a, C> {
    // The struct that will receive content / rules.
    content_visitor: C,

    // This is a list of parent tree nodes, which is a list of all of the "active" rule changes.
    // If an "Add" exists for a rule in this list, it will be scanned. If a single "Remove" exists, it will cause the `ExclusionCheck` to return true.
    tree_nodes: Vec<ActiveRuleTree<'a>>,

    #[allow(dead_code)]
    // This is a list of rule indices that have been detected as true positives for the current path.
    true_positive_rule_idx: Vec<usize>,

    // This is a list of sanitized segments until the current node.
    // It contains Options because the segments can be Indexes, not Fields. Fields have a path, Index don't and will result in None instead.
    sanitized_segments_until_node: Vec<Option<Cow<'a, str>>>,

    // This is a counter that helps keep track of how many elements we have pushed
    // In the tree_nodes list and in the true_positive_rule_idx list
    active_node_counter: Vec<NodeCounter>,

    // The current path being visited
    path: Path<'a>,

    // A re-usable boolean set to de-duplicate rules
    bool_set: Option<BoolSet>,

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
        let active_trees_range = tree_nodes_len - num_active_trees..tree_nodes_len;

        for tree_index in active_trees_range {
            if !self.tree_nodes[tree_index].index_wildcard_match || !segment.is_index() {
                if let Some(child) = self.tree_nodes[tree_index].rule_tree.children.get(&segment) {
                    self.tree_nodes.push(ActiveRuleTree {
                        rule_tree: child,
                        index_wildcard_match: false,
                    });
                }
            }

            if self.add_implicit_index_wildcards && segment.is_index() {
                // Optionally skip the index (it acts as a wildcard) by
                // pushing the same tree back onto the stack.
                self.tree_nodes.push(ActiveRuleTree {
                    rule_tree: self.tree_nodes[tree_index].rule_tree,
                    index_wildcard_match: true,
                });
            }
        }

        // Sanitize the segment and push it. If the segment is an Index, it will push None.
        // I'm testing another way of performing the included keywords on path, so I simply push None here.
        self.sanitized_segments_until_node.push(None);

        // I'm testing another way of performing the included keywords on path feature, so this will be cleaned soon.
        let true_positive_rules_count = if false {
            let mut total_len: usize = self
                .sanitized_segments_until_node
                .iter()
                .flatten()
                .map(|x| x.len() + 1)
                .sum();

            // This will remove 1 to the total_len only if the result is >= 0
            total_len = total_len.saturating_sub(1);

            let mut current_sanitized_path = String::with_capacity(total_len);
            for (i, segment) in self
                .sanitized_segments_until_node
                .iter()
                .flatten()
                .enumerate()
            {
                if i != 0 {
                    current_sanitized_path.push(UNIFIED_LINK_CHAR);
                }
                current_sanitized_path.push_str(segment.as_ref());
            }

            self.content_visitor
                .find_true_positive_rules_from_current_path(
                    current_sanitized_path.as_str(),
                    &mut self.true_positive_rule_idx,
                )
        } else {
            0
        };

        // The new number of active trees is the number of new trees pushed
        self.active_node_counter.push(NodeCounter {
            active_tree_count: self.tree_nodes.len() - tree_nodes_len,
            true_positive_rules_count,
        });

        self.path.segments.push(segment);
    }

    fn pop_segment(&mut self) {
        let node_counter = self.active_node_counter.pop().unwrap();
        for _ in 0..node_counter.active_tree_count {
            // The rules from the last node are no longer active, so remove them.
            let _popped = self.tree_nodes.pop();
        }
        for _ in 0..node_counter.true_positive_rules_count {
            // The true positive rule indices from the last node are no longer active, remove them.
            let _popped = self.true_positive_rule_idx.pop();
        }
        // Pop the sanitized segment
        self.sanitized_segments_until_node.pop();
        self.path.segments.pop();
    }

    fn visit_string<'s>(&'s mut self, value: &str) -> VisitStringResult<'s, 'path> {
        let will_mutate = self.content_visitor.visit_content(
            &self.path,
            value,
            RuleIndexVisitor {
                tree_nodes: &self.tree_nodes,
                used_rule_set: self.bool_set.as_mut(),
            },
            ExclusionCheck {
                tree_nodes: &self.tree_nodes,
            },
            &self.true_positive_rule_idx,
        );
        if let Some(bool_set) = &mut self.bool_set {
            bool_set.reset();
        }
        VisitStringResult {
            might_mutate: will_mutate,
            path: &self.path,
        }
    }
}

pub struct RuleIndexVisitor<'a> {
    tree_nodes: &'a Vec<ActiveRuleTree<'a>>,
    used_rule_set: Option<&'a mut BoolSet>,
}

impl<'a> RuleIndexVisitor<'a> {
    /// Visits all rules associated with the current string. This may
    /// potentially return no rule indices at all.
    pub fn visit_rule_indices(&mut self, mut visit: impl FnMut(usize)) {
        // visit rules with an `Include` scope
        for include_node in self.tree_nodes {
            if include_node.index_wildcard_match {
                // This is guaranteed to be a duplicated node. Skip it
                continue;
            }
            for change in &include_node.rule_tree.rule_changes {
                match change {
                    RuleChange::Add(rule_index) => {
                        if let Some(used_rule_set) = &mut self.used_rule_set {
                            if !used_rule_set.get_and_set(*rule_index) {
                                (visit)(*rule_index);
                            }
                        } else {
                            (visit)(*rule_index);
                        }
                    }
                    RuleChange::Remove(_) => { /* Nothing to do here */ }
                }
            }
        }
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
    pub fn new() -> Self {
        Self {
            rule_changes: vec![],
            children: AHashMap::new(),
        }
    }

    pub fn insert_rule_add(&mut self, path: &Path<'static>, rule_index: usize) {
        self.insert_rule_inner(&path.segments, RuleChange::Add(rule_index));
    }

    pub fn insert_rule_removal(&mut self, path: &Path<'static>, rule_index: usize) {
        self.insert_rule_inner(&path.segments, RuleChange::Remove(rule_index));
    }

    fn insert_rule_inner(&mut self, path: &[PathSegment<'static>], rule_change: RuleChange) {
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
            // remove any recursive children, since they will be duplicated
            self.recursively_remove(rule_change);
            self.rule_changes.push(rule_change);
        }
    }

    // Remove the given change from all children (recursive). This is used
    // to remove duplicates.
    fn recursively_remove(&mut self, rule_change: RuleChange) {
        self.rule_changes.retain(|x| *x != rule_change);
        for child_tree in self.children.values_mut() {
            child_tree.recursively_remove(rule_change);
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
                _true_positive_rule_idx: &[usize],
            ) -> bool {
                let mut rules = vec![];
                rule_iter.visit_rule_indices(|rule_index| {
                    rules.push(VisitedRule {
                        rule_index,
                        is_excluded: exclusion_check.is_excluded(rule_index),
                    });
                });
                rules.sort();
                self.visited.paths.push(VisitedPath {
                    path: path.into_static(),
                    content: content.to_string(),
                    rules,
                });
                true
            }

            fn find_true_positive_rules_from_current_path(
                &self,
                _sanitized_path: &str,
                _current_true_positive_rule_idx: &mut Vec<usize>,
            ) -> usize {
                0
            }
        }

        ruleset.visit_string_rule_combinations(
            event,
            RecordingContentVisitor {
                visited: &mut visited,
            },
        );
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
}
