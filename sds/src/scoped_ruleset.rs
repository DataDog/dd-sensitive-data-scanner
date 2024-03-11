use crate::event::{EventVisitor, VisitStringResult};
use crate::{Event, Path, PathSegment, Scope};
use ahash::AHashMap;

/// A `ScopedRuleSet` determines which rules will be used to scan each field of an event, and which
/// paths are considered `excluded`.
#[derive(Debug)]
pub struct ScopedRuleSet {
    tree: RuleTree,
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
        Self { tree }
    }

    pub fn visit_string_rule_combinations<'path, 'c: 'path>(
        &'c self,
        event: &'path mut impl Event,
        content_visitor: impl ContentVisitor<'path>,
    ) {
        let mut visitor = ScopedRuledSetEventVisitor {
            content_visitor,
            tree_nodes: vec![&self.tree],
            path: Path::root(),
        };

        event.visit_event(&mut visitor)
    }
}

pub struct ExclusionCheck<'a> {
    tree_nodes: &'a [&'a RuleTree],
}
impl<'a> ExclusionCheck<'a> {
    pub fn is_excluded(&self, rule_index: usize) -> bool {
        for include_node in self.tree_nodes {
            for change in &include_node.rule_changes {
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
    ) -> bool;
}

struct ScopedRuledSetEventVisitor<'a, C> {
    // The struct that will receive content / rules.
    content_visitor: C,

    // This is a list of parent tree nodes, which is a list of all of the "active" rule changes.
    // If an "Add" exists for a rule in this list, it will be scanned. If a single "Remove" exists, it will cause the `ExclusionCheck` to return true.
    tree_nodes: Vec<&'a RuleTree>,

    // The current path being visited
    path: Path<'a>,
}

impl<'path: 'content_visitor, 'content_visitor, C> EventVisitor<'path>
    for ScopedRuledSetEventVisitor<'path, C>
where
    C: ContentVisitor<'path>,
{
    fn push_segment(&mut self, segment: PathSegment<'path>) {
        // update the tree
        // The current path may go beyond what is stored in the "include" tree, so the tree is only updated if they are at the same height.
        if self.path.len() + 1 == self.tree_nodes.len() {
            let last_tree = *self.tree_nodes.last().unwrap();
            if let Some(child) = last_tree.children.get(&segment) {
                // All of the rules from the `child` node should be applied to the current path (and anything below it)
                self.tree_nodes.push(child);
            }
        }

        self.path.segments.push(segment);
    }

    fn pop_segment(&mut self) {
        if self.path.len() + 1 == self.tree_nodes.len() {
            // The rules from the last node are no longer active, so remove them.
            let _popped = self.tree_nodes.pop();
        }
        self.path.segments.pop();
    }

    fn visit_string<'s>(&'s mut self, value: &str) -> VisitStringResult<'s, 'path> {
        let will_mutate = self.content_visitor.visit_content(
            &self.path,
            value,
            RuleIndexVisitor {
                tree_nodes: &self.tree_nodes,
            },
            ExclusionCheck {
                tree_nodes: &self.tree_nodes,
            },
        );
        VisitStringResult {
            will_mutate,
            path: &self.path,
        }
    }
}

pub struct RuleIndexVisitor<'a> {
    tree_nodes: &'a Vec<&'a RuleTree>,
}

impl<'a> RuleIndexVisitor<'a> {
    /// Visits all rules associated with the current string. This may
    /// potentially return no rule indices at all.
    pub fn visit_rule_indices(&self, mut visit: impl FnMut(usize)) {
        // visit rules with an `Include` scope
        for include_node in self.tree_nodes {
            for change in &include_node.rule_changes {
                match change {
                    RuleChange::Add(rule_id) => {
                        (visit)(*rule_id);
                    }
                    RuleChange::Remove(_) => {
                        /* ignore removals, they can be checked as needed later */
                    }
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

    #[derive(Debug, PartialEq, Eq)]
    struct Visited {
        paths: Vec<(Path<'static>, String, Vec<(usize, bool)>)>,
    }

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
                rule_iter: RuleIndexVisitor,
                exclusion_check: ExclusionCheck<'content_visitor>,
            ) -> bool {
                let mut rules = vec![];
                rule_iter.visit_rule_indices(|rule_index| {
                    rules.push((rule_index, exclusion_check.is_excluded(rule_index)));
                });
                rules.sort();
                self.visited
                    .paths
                    .push((path.into_static(), content.to_string(), rules));
                true
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
        let ruleset = ScopedRuleSet::new(&[
            Scope::include(vec![Path::from(vec!["a".into()])]),
            Scope::include(vec![Path::from(vec!["a".into(), "b".into()])]),
            Scope::none(),
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
                    (
                        Path::from(vec!["a".into(), "b".into()]),
                        "value-ab".into(),
                        vec![(0, false), (1, false)]
                    ),
                    (
                        Path::from(vec!["a".into(), "c".into()]),
                        "value-ac".into(),
                        vec![(0, false)]
                    ),
                    (Path::from(vec!["d".into()]), "value-d".into(), vec![])
                ],
            }
        );
    }

    #[test]
    fn test_inclusive_scopes_array() {
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
                    (
                        Path::from(vec![0.into()]),
                        "value-0".into(),
                        vec![(0, false)]
                    ),
                    (Path::from(vec![1.into()]), "value-1".into(), vec![]),
                    (
                        Path::from(vec![2.into(), 0.into()]),
                        "value-2-0".into(),
                        vec![(2, false)]
                    ),
                    (Path::from(vec![3.into()]), "value-3".into(), vec![]),
                ],
            }
        );
    }

    #[test]
    fn test_exclusive_scopes() {
        let ruleset = ScopedRuleSet::new(&[
            Scope::exclude(vec![Path::from(vec!["a".into()])]),
            Scope::exclude(vec![Path::from(vec!["a".into(), "b".into()])]),
            // matches everything
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
                    (
                        Path::from(vec!["a".into(), "b".into()]),
                        "value-ab".into(),
                        vec![(0, true), (1, true), (2, false)]
                    ),
                    (
                        Path::from(vec!["a".into(), "c".into()]),
                        "value-ac".into(),
                        vec![(0, true), (1, false), (2, false)]
                    ),
                    (
                        Path::from(vec!["d".into()]),
                        "value-d".into(),
                        vec![(0, false), (1, false), (2, false)]
                    )
                ],
            },
        );
    }

    #[test]
    fn test_exclusive_scopes_array() {
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
                    (
                        Path::from(vec![0.into()]),
                        "value-0".into(),
                        vec![(0, true), (1, false), (2, false)]
                    ),
                    (
                        Path::from(vec![1.into()]),
                        "value-1".into(),
                        vec![(0, false), (1, false), (2, false)]
                    ),
                    (
                        Path::from(vec![2.into(), 0.into()]),
                        "value-2-0".into(),
                        vec![(0, false), (1, false), (2, true)]
                    ),
                    (
                        Path::from(vec![3.into()]),
                        "value-3".into(),
                        vec![(0, false), (1, false), (2, false)]
                    ),
                ],
            }
        );
    }

    #[test]
    fn test_include_and_exclude() {
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
                    (Path::from(vec![0.into()]), "value-0".into(), vec![]),
                    (Path::from(vec![1.into()]), "value-1".into(), vec![]),
                    (
                        Path::from(vec![2.into(), 0.into()]),
                        "value-2-0".into(),
                        vec![(0, true)]
                    ),
                    (
                        Path::from(vec![2.into(), 1.into()]),
                        "value-2-1".into(),
                        vec![(0, false)]
                    ),
                    (Path::from(vec![3.into()]), "value-3".into(), vec![]),
                ],
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
                    (Path::from(vec![0.into()]), "value-0".into(), vec![]),
                    (
                        Path::from(vec![1.into(), 0.into()]),
                        "value-1-0".into(),
                        vec![(0, true)]
                    ),
                    (
                        Path::from(vec![1.into(), 1.into()]),
                        "value-1-1".into(),
                        vec![]
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
                    (
                        Path::from(vec!["a".into(), "b".into()]),
                        "value-ab".into(),
                        vec![(0, false)]
                    ),
                    (
                        Path::from(vec!["a".into(), "c".into()]),
                        "value-ac".into(),
                        vec![(0, false)]
                    ),
                    (Path::from(vec!["d".into()]), "value-d".into(), vec![])
                ],
            }
        );
    }

    #[test]
    fn test_include_root_multiple_times() {
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
                    (
                        Path::from(vec!["a".into(), "b".into()]),
                        "value-ab".into(),
                        vec![(0, false)]
                    ),
                    (
                        Path::from(vec!["a".into(), "c".into()]),
                        "value-ac".into(),
                        vec![(0, false)]
                    ),
                    (
                        Path::from(vec!["d".into()]),
                        "value-d".into(),
                        vec![(0, false)]
                    )
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
                    (
                        Path::from(vec!["a".into(), "b".into()]),
                        "value-ab".into(),
                        vec![(0, false)]
                    ),
                    (
                        Path::from(vec!["a".into(), "c".into()]),
                        "value-ac".into(),
                        vec![(0, false)]
                    ),
                    (Path::from(vec!["d".into()]), "value-d".into(), vec![])
                ],
            }
        );
    }
}
