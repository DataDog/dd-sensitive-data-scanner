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
