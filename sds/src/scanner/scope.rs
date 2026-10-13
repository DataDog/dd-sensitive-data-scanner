use crate::Path;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "paths")]
pub enum Scope {
    // Only `include` fields are scanned,
    Include {
        include: Vec<Path<'static>>,
        exclude: Vec<Path<'static>>,
    },
    // Everything is scanned except the list of fields (children are also excluded)
    Exclude(Vec<Path<'static>>),
}

impl Scope {
    /// All fields of the event are scanned
    pub fn all() -> Self {
        Self::Exclude(vec![])
    }

    /// Paths will be scanned if they are children of any `include` path and NOT children of any `exclude` path
    pub fn include_and_exclude(include: Vec<Path<'static>>, exclude: Vec<Path<'static>>) -> Self {
        Self::Include { include, exclude }
    }

    /// Paths will be scanned if they are children of any `include` path
    pub fn include(include: Vec<Path<'static>>) -> Self {
        Self::Include {
            include,
            exclude: vec![],
        }
    }

    /// Paths will be scanned if they are NOT children of any `exclude` path
    pub fn exclude(exclude: Vec<Path<'static>>) -> Self {
        Self::Exclude(exclude)
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
