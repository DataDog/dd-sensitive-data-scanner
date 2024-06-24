use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::{encoding::Utf8Encoding, Event, EventVisitor, Path, PathSegment};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MessageFirstKey(String);

impl MessageFirstKey {
    fn as_str(&self) -> &str {
        &self.0
    }
    pub fn new(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for MessageFirstKey {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Ord for MessageFirstKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.0.as_str(), other.0.as_str()) {
            ("message", "message") => Ordering::Equal,
            ("message", _) => Ordering::Less,
            (_, "message") => Ordering::Greater,
            (_, _) => self.0.cmp(&other.0),
        }
    }
}

impl PartialOrd for MessageFirstKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A simple implementation of `Event`. This is meant for testing / demonstration purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleEvent {
    String(String),
    List(Vec<SimpleEvent>),
    Map(BTreeMap<MessageFirstKey, SimpleEvent>),
}

impl Event for SimpleEvent {
    type Encoding = Utf8Encoding;

    fn visit_event<'path>(&'path mut self, visitor: &mut impl EventVisitor<'path>) {
        match self {
            Self::String(value) => {
                let _result = visitor.visit_string(value);
            }
            Self::List(list) => {
                for (i, child) in list.iter_mut().enumerate() {
                    visitor.push_segment(PathSegment::Index(i));
                    child.visit_event(visitor);
                    visitor.pop_segment();
                }
            }
            Self::Map(map) => {
                for (key, child) in map.iter_mut() {
                    visitor.push_segment(key.as_str().into());
                    child.visit_event(visitor);
                    visitor.pop_segment();
                }
            }
        }
    }

    fn visit_string_mut(&mut self, path: &Path, mut visit: impl FnMut(&mut String) -> bool) {
        let mut value = self;

        for segment in &path.segments {
            match segment {
                PathSegment::Field(key) => {
                    let key_ref = MessageFirstKey::from(key.as_ref());
                    value = value.as_map_mut().unwrap().get_mut(&key_ref).unwrap();
                }
                PathSegment::Index(i) => {
                    value = value.as_list_mut().unwrap().get_mut(*i).unwrap();
                }
            }
        }
        (visit)(value.as_string_mut().unwrap());
    }
}

impl SimpleEvent {
    /// Gets a mutable reference to the list.
    pub fn as_list_mut(&mut self) -> Option<&mut Vec<SimpleEvent>> {
        match self {
            Self::List(x) => Some(x),
            _ => None,
        }
    }

    /// Gets a mutable reference to the map.
    pub fn as_map_mut(&mut self) -> Option<&mut BTreeMap<MessageFirstKey, SimpleEvent>> {
        match self {
            Self::Map(x) => Some(x),
            _ => None,
        }
    }

    /// Gets a mutable reference to the map.
    pub fn as_string_mut(&mut self) -> Option<&mut String> {
        match self {
            Self::String(x) => Some(x),
            _ => None,
        }
    }
}
