use std::collections::BTreeMap;

use crate::{encoding::Utf8Encoding, Event, EventVisitor, Path, PathSegment, ScannerError};

static FIRST_VISIT_KEY: &str = "message";

/// A simple implementation of `Event`. This is meant for testing / demonstration purposes.
/// It always start visiting elements with key == "message" first, then the rest of the keys in the map
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleEvent {
    String(String),
    List(Vec<SimpleEvent>),
    Map(BTreeMap<String, SimpleEvent>),
}

impl Event for SimpleEvent {
    type Encoding = Utf8Encoding;

    fn visit_event<'path>(
        &'path mut self,
        visitor: &mut impl EventVisitor<'path>,
    ) -> Result<(), ScannerError> {
        match self {
            Self::String(value) => visitor.visit_string(value).map(|_| {}),
            Self::List(list) => {
                for (i, child) in list.iter_mut().enumerate() {
                    visitor.push_segment(PathSegment::Index(i));
                    if let Err(e) = child.visit_event(visitor) {
                        return Err(e);
                    }
                    visitor.pop_segment();
                }
                Ok(())
            }
            Self::Map(map) => {
                // Create a data structure holding the key that will be processed after the message key
                let mut key_to_post_process: Vec<(&String, &mut SimpleEvent)> = vec![];
                for (key, child) in map.iter_mut() {
                    if key == FIRST_VISIT_KEY {
                        visitor.push_segment(key.as_str().into());
                        if let Err(e) = child.visit_event(visitor) {
                            return Err(e);
                        }
                        visitor.pop_segment();
                    } else {
                        key_to_post_process.push((key, child));
                    }
                }
                for (key, child) in key_to_post_process {
                    visitor.push_segment(key.as_str().into());
                    if let Err(e) = child.visit_event(visitor) {
                        return Err(e);
                    }
                    visitor.pop_segment();
                }
                Ok(())
            }
        }
    }

    fn visit_string_mut(&mut self, path: &Path, mut visit: impl FnMut(&mut String) -> bool) {
        let mut value = self;

        for segment in &path.segments {
            match segment {
                PathSegment::Field(key) => {
                    value = value.as_map_mut().unwrap().get_mut(key.as_ref()).unwrap();
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
    pub fn as_map_mut(&mut self) -> Option<&mut BTreeMap<String, SimpleEvent>> {
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
