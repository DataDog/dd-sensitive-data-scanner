use crate::event::{EventVisitor, VisitStringResult};
use crate::{Event, Path, PathSegment, Scope};
use ahash::{AHashMap, AHashSet};

/// A `ScopedRuleSet` determines which rules will be used to scan each field of an event.
pub struct ScopedRuleSet {
    include_tree: RuleTree,
    exclude_tree: RuleTree,
    initial_exclude_rules: AHashSet<usize>,
}

impl ScopedRuleSet {
    /// The scopes for each rule. The indices of the scopes MUST match the rule index.
    pub fn new(rules_scopes: &[Scope]) -> Self {
        let mut include_tree = RuleTree::new();
        let mut exclude_tree = RuleTree::new();
        let mut initial_exclude_rules = AHashSet::new();

        for (rule_index, scope) in rules_scopes.iter().enumerate() {
            match &scope {
                Scope::Include(paths) => {
                    for path in paths {
                        include_tree.insert_rule(path, rule_index);
                    }
                }
                Scope::Exclude(paths) => {
                    initial_exclude_rules.insert(rule_index);
                    for path in paths {
                        exclude_tree.insert_rule(path, rule_index);
                    }
                }
                Scope::All => {
                    // TODO: This variant should not exist (Should be Exclude(vec![]) instead)
                    include_tree.insert_rule(&Path::root(), rule_index);
                }
            }
        }
        Self {
            include_tree,
            exclude_tree,
            initial_exclude_rules,
        }
    }

    pub fn visit_string_rule_combinations(
        &self,
        event: &mut impl Event,
        visit: impl FnMut(&Path, &str, RuleIndexVisitor) -> bool,
    ) {
        event.visit_event(&mut ScopedRuledSetEventVisitor {
            visit,
            include_tree_nodes: vec![&self.include_tree],
            exclude_tree_nodes: vec![&self.exclude_tree],
            path: Path::root(),
            exclusion_rule_ids: self.initial_exclude_rules.clone(),
        })
    }
}

struct ScopedRuledSetEventVisitor<'a, F> {
    visit: F,

    // `include_tree_nodes` is a list of all the nodes from the root to the current node.
    // This list contains all of the tree nodes that ADD rules, so iterating all of the rules
    // requires simply iterating through this list. Going deeper in the tree (pushing a segment)
    // adds to this list, and going back up (popping a segment) removes from the list.
    include_tree_nodes: Vec<&'a RuleTree>,

    // `exclude_tree_nodes` is a list of all the nodes from the root to the current node.
    // This list contains all of the tree nodes that REMOVE rules. The actual active rules with
    // excluded scopes are kept in `exclusion_rule_ids`. This is just used to remember which rules
    // need to be removed as you go back up the tree (segments are popped from the event).
    exclude_tree_nodes: Vec<&'a RuleTree>,

    // The current path being visited
    path: Path<'a>,

    // The current list of rules that had `Exclude` scopes. This starts as the whole list.
    // They are removed as nodes are pushed, and inserted when they are popped.
    exclusion_rule_ids: AHashSet<usize>,
}

impl<'a, F> EventVisitor<'a> for ScopedRuledSetEventVisitor<'a, F>
where
    F: FnMut(&Path<'a>, &str, RuleIndexVisitor) -> bool,
{
    fn push_segment(&mut self, segment: PathSegment<'a>) {
        // update include tree
        // The current path may go beyond what is stored in the "include" tree, so the tree is only updated if they are at the same height.
        if self.path.len() + 1 == self.include_tree_nodes.len() {
            let last_tree = *self.include_tree_nodes.last().unwrap();
            if let Some(child) = last_tree.children.get(&segment) {
                // All of the rules from the `child` node should be applied to the current path (and anything below it)
                self.include_tree_nodes.push(child);
            }
        }

        // update exclude tree
        // The current path may go beyond what is stored in the "exclude" tree, so the tree is only updated if they are at the same height.
        if self.path.len() + 1 == self.exclude_tree_nodes.len() {
            let last_tree = *self.exclude_tree_nodes.last().unwrap();
            if let Some(child) = last_tree.children.get(&segment) {
                for rule_id in &child.rules_ids {
                    // All rules included in this node will now be excluded, so it's removed from the `exclusion_rule_ids` set.
                    let was_present = self.exclusion_rule_ids.remove(rule_id);
                    debug_assert!(was_present);
                }

                // Save the tree node for later so the rules stored in it can be added back to the `exclusion_rule_ids` when the segment is popped
                self.exclude_tree_nodes.push(child);
            }
        }

        self.path.segments.push(segment);
    }

    fn pop_segment(&mut self) {
        if self.path.len() + 1 == self.include_tree_nodes.len() {
            // The rules from the last node are no longer active, so remove them.
            self.include_tree_nodes.pop();
        }

        if self.path.len() + 1 == self.exclude_tree_nodes.len() {
            let popped = self.exclude_tree_nodes.pop().unwrap();
            for rule_id in &popped.rules_ids {
                // The rules from the latest node are no longer being excluded, so add them back to the `exclusion_rule_ids` set.
                self.exclusion_rule_ids.insert(*rule_id);
            }
        }
        self.path.segments.pop();
    }

    fn visit_string<'b>(&'b mut self, value: &str) -> VisitStringResult<'b, 'a> {
        let will_mutate = (self.visit)(
            &self.path,
            value,
            RuleIndexVisitor {
                include_tree_nodes: &self.include_tree_nodes,
                exclusion_rule_ids: &self.exclusion_rule_ids,
            },
        );
        VisitStringResult {
            will_mutate,
            path: &self.path,
        }
    }
}

pub struct RuleIndexVisitor<'a> {
    include_tree_nodes: &'a Vec<&'a RuleTree>,
    exclusion_rule_ids: &'a AHashSet<usize>,
}

impl<'a> RuleIndexVisitor<'a> {
    /// Visits all rules associated with the current string. This may
    /// potentially return no rule indices at all.
    pub fn visit_rule_indices(&self, mut visit: impl FnMut(usize)) {
        // visit rules with an `Include` scope
        for include_node in self.include_tree_nodes {
            for rule_id in &include_node.rules_ids {
                (visit)(*rule_id);
            }
        }

        // visit rules with an `Exclude` scope
        for rule_id in self.exclusion_rule_ids {
            (visit)(*rule_id)
        }
    }
}

#[derive(Clone)]
struct RuleTree {
    rules_ids: Vec<usize>,
    children: AHashMap<PathSegment<'static>, RuleTree>,
}

impl RuleTree {
    pub fn new() -> Self {
        Self {
            rules_ids: vec![],
            children: AHashMap::new(),
        }
    }

    pub fn insert_rule(&mut self, path: &Path<'static>, rule_index: usize) {
        self.insert_rule_inner(&path.segments, rule_index);
    }

    fn insert_rule_inner(&mut self, path: &[PathSegment<'static>], rule_index: usize) {
        if let Some((first, remaining)) = path.split_first() {
            let child_tree = self
                .children
                .entry(first.clone())
                .or_insert_with(RuleTree::new);
            child_tree.insert_rule_inner(remaining, rule_index);
        } else {
            self.rules_ids.push(rule_index);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::simple_event::SimpleEvent;

    use super::*;

    fn visit_event(
        event: &mut impl Event,
        ruleset: &ScopedRuleSet,
    ) -> Vec<(Path<'static>, String, Vec<usize>)> {
        let mut paths = vec![];
        ruleset.visit_string_rule_combinations(event, |path, value, rule_iter| {
            let mut rules_for_path = vec![];
            rule_iter.visit_rule_indices(|rule_index| {
                rules_for_path.push(rule_index);
            });
            rules_for_path.sort();
            paths.push((path.into_static(), value.to_string(), rules_for_path));
            true
        });
        paths.sort();
        paths
    }

    #[test]
    fn test_inclusive_scopes() {
        let ruleset = ScopedRuleSet::new(&[
            Scope::Include(vec![Path::from(vec!["a".into()])]),
            Scope::Include(vec![Path::from(vec!["a".into(), "b".into()])]),
            // matches nothing
            Scope::Include(vec![]),
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
            vec![
                (
                    Path::from(vec!["a".into(), "b".into()]),
                    "value-ab".into(),
                    vec![0, 1]
                ),
                (
                    Path::from(vec!["a".into(), "c".into()]),
                    "value-ac".into(),
                    vec![0]
                ),
                (Path::from(vec!["d".into()]), "value-d".into(), vec![])
            ]
        );
    }

    #[test]
    fn test_inclusive_scopes_array() {
        let ruleset = ScopedRuleSet::new(&[
            Scope::Include(vec![Path::from(vec![0.into()])]),
            Scope::Include(vec![Path::from(vec![1.into(), 0.into()])]),
            Scope::Include(vec![Path::from(vec![2.into(), 0.into()])]),
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
            vec![
                (Path::from(vec![0.into()]), "value-0".into(), vec![0]),
                (Path::from(vec![1.into()]), "value-1".into(), vec![]),
                (
                    Path::from(vec![2.into(), 0.into()]),
                    "value-2-0".into(),
                    vec![2]
                ),
                (Path::from(vec![3.into()]), "value-3".into(), vec![]),
            ]
        );
    }

    #[test]
    fn test_exclusive_scopes() {
        let ruleset = ScopedRuleSet::new(&[
            Scope::Exclude(vec![Path::from(vec!["a".into()])]),
            Scope::Exclude(vec![Path::from(vec!["a".into(), "b".into()])]),
            // matches everything
            Scope::Exclude(vec![]),
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
            vec![
                (
                    Path::from(vec!["a".into(), "b".into()]),
                    "value-ab".into(),
                    vec![2]
                ),
                (
                    Path::from(vec!["a".into(), "c".into()]),
                    "value-ac".into(),
                    vec![1, 2]
                ),
                (
                    Path::from(vec!["d".into()]),
                    "value-d".into(),
                    vec![0, 1, 2]
                )
            ]
        );
    }

    #[test]
    fn test_exclusive_scopes_array() {
        let ruleset = ScopedRuleSet::new(&[
            Scope::Exclude(vec![Path::from(vec![0.into()])]),
            Scope::Exclude(vec![Path::from(vec![1.into(), 0.into()])]),
            Scope::Exclude(vec![Path::from(vec![2.into(), 0.into()])]),
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
            vec![
                (Path::from(vec![0.into()]), "value-0".into(), vec![1, 2]),
                (Path::from(vec![1.into()]), "value-1".into(), vec![0, 1, 2]),
                (
                    Path::from(vec![2.into(), 0.into()]),
                    "value-2-0".into(),
                    vec![0, 1]
                ),
                (Path::from(vec![3.into()]), "value-3".into(), vec![0, 1, 2]),
            ]
        );
    }
}
