use crate::Path;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanArea {
    #[default]
    Everything,
    /// An empty list means the rule never runs.
    Only(Vec<Path<'static>>),
}

/// Which fields of an event a rule looks at.
///
/// A path covers itself and all of its children. When a field is covered by both `include`
/// and `exclude`, `exclude` wins, even if the `include` path is more specific.
///
/// Excluded fields are not always skipped. Regex rules still scan them and don't report those
/// matches, and with multipass V0 enabled, the same value matched elsewhere in the event is
/// dropped as well. Other rules skip excluded fields.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
// Rejecting unknown fields makes a scope in an older JSON format fail loudly instead of
// parsing as "scan everything".
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    pub(crate) include: ScanArea,
    /// Matches in these fields are not reported (see the type docs for what regex rules still
    /// do with them).
    #[serde(default)]
    pub(crate) exclude: Vec<Path<'static>>,
}

impl Scope {
    /// Covers every field of the event.
    pub fn all() -> Self {
        Self {
            include: ScanArea::Everything,
            exclude: vec![],
        }
    }

    /// Covers fields under any `include` path, minus fields under any `exclude` path.
    pub fn include_and_exclude(include: Vec<Path<'static>>, exclude: Vec<Path<'static>>) -> Self {
        Self {
            include: ScanArea::Only(include),
            exclude,
        }
    }

    /// Covers only fields under any `include` path. An empty `include` means the rule never runs.
    pub fn include(include: Vec<Path<'static>>) -> Self {
        Self {
            include: ScanArea::Only(include),
            exclude: vec![],
        }
    }

    /// Covers every field, minus fields under any `exclude` path.
    pub fn exclude(exclude: Vec<Path<'static>>) -> Self {
        Self {
            include: ScanArea::Everything,
            exclude,
        }
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self::all()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::{Value, json};

    fn field_path(name: &'static str) -> Path<'static> {
        Path::from(vec![name.into()])
    }

    fn field_path_json(name: &str) -> Value {
        json!({"segments": [{"type": "Field", "value": name}]})
    }

    fn assert_json_round_trip(scope: Scope, expected: Value) {
        assert_eq!(serde_json::to_value(&scope).unwrap(), expected);
        assert_eq!(serde_json::from_value::<Scope>(expected).unwrap(), scope);
    }

    #[test]
    fn test_all_scope_json() {
        assert_json_round_trip(
            Scope::all(),
            json!({"include": "everything", "exclude": []}),
        );
    }

    #[test]
    fn test_default_scope_is_all() {
        assert_eq!(Scope::default(), Scope::all());
    }

    #[test]
    fn test_include_scope_json() {
        assert_json_round_trip(
            Scope::include(vec![field_path("a")]),
            json!({"include": {"only": [field_path_json("a")]}, "exclude": []}),
        );
    }

    #[test]
    fn test_include_nothing_scope_json_differs_from_all() {
        assert_json_round_trip(
            Scope::include(vec![]),
            json!({"include": {"only": []}, "exclude": []}),
        );
    }

    #[test]
    fn test_exclude_scope_json() {
        assert_json_round_trip(
            Scope::exclude(vec![field_path("a")]),
            json!({"include": "everything", "exclude": [field_path_json("a")]}),
        );
    }

    #[test]
    fn test_include_and_exclude_scope_json() {
        assert_json_round_trip(
            Scope::include_and_exclude(vec![field_path("a")], vec![field_path("b")]),
            json!({"include": {"only": [field_path_json("a")]}, "exclude": [field_path_json("b")]}),
        );
    }

    #[test]
    fn test_missing_scope_fields_default_to_all() {
        assert_eq!(
            serde_json::from_value::<Scope>(json!({})).unwrap(),
            Scope::all()
        );
    }

    // Old-format JSON must fail loudly: with defaulted fields it would otherwise
    // parse as "scan everything".
    #[test]
    fn test_old_scope_json_format_is_rejected() {
        assert!(serde_json::from_value::<Scope>(json!({"type": "Exclude", "paths": []})).is_err());
        assert!(
            serde_json::from_value::<Scope>(
                json!({"type": "Include", "paths": {"include": [], "exclude": []}})
            )
            .is_err()
        );
    }
}
