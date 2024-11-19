use core::panic;
use std::collections::HashMap;
use std::hash::RandomState;

use crate::{Event, EventVisitor, Path, PathSegment, Utf8Encoding};

impl Event for serde_json::Value {
    type Encoding = Utf8Encoding;

    fn visit_event<'a>(&'a mut self, visitor: &mut impl EventVisitor<'a>) {
        match self {
            serde_json::Value::Null => {}
            serde_json::Value::Bool(value) => {
                let _result = visitor.visit_string(value.to_string().as_str());
            }
            serde_json::Value::Number(number) => {
                let _result = visitor.visit_string(number.to_string().as_str());
            }
            serde_json::Value::String(s) => {
                let _result = visitor.visit_string(s);
            }
            serde_json::Value::Object(map) => {
                for (k, child) in map.iter_mut() {
                    visitor.push_segment(k.as_str().into());
                    child.visit_event(visitor);
                    visitor.pop_segment();
                }
            }
            serde_json::Value::Array(values) => {
                for (i, value) in values.iter_mut().enumerate() {
                    visitor.push_segment(PathSegment::Index(i));
                    value.visit_event(visitor);
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
                    value = value
                        .as_object_mut()
                        .unwrap()
                        .get_mut(key.as_ref())
                        .unwrap();
                }
                PathSegment::Index(i) => {
                    value = value.as_array_mut().unwrap().get_mut(*i).unwrap();
                }
            }
        }
        match value {
            serde_json::Value::String(s) => {
                (visit)(s);
            }
            _ => panic!("unknown value"),
        };
    }
}

impl Event for HashMap<String, serde_json::Value, RandomState> {
    type Encoding = Utf8Encoding;

    fn visit_event<'a>(&'a mut self, visitor: &mut impl EventVisitor<'a>) {
        for (k, v) in self.iter_mut() {
            visitor.push_segment(PathSegment::Field(k.as_str().into()));
            v.visit_event(visitor);
            visitor.pop_segment();
        }
    }

    fn visit_string_mut(&mut self, path: &Path, mut visit: impl FnMut(&mut String) -> bool) {
        let first_segment = path.segments.first().unwrap();
        let mut remaining_segments = path.segments.clone();
        remaining_segments.remove(0);
        if let PathSegment::Field(field) = first_segment {
            let value = self.get_mut(&field.to_string()).unwrap();
            value.visit_string_mut(&Path::from(remaining_segments), &mut visit);
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use serde_json::{json, Map, Value};

    use crate::VisitStringResult;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum VisitOp {
        Push(PathSegment<'static>),
        Pop,
        Visit(String),
    }

    struct Visitor {
        path: Path<'static>,
        ops: Vec<VisitOp>,
    }

    impl<'path> EventVisitor<'path> for Visitor {
        fn push_segment(&mut self, segment: PathSegment<'path>) {
            self.ops.push(VisitOp::Push(segment.into_static()));
        }

        fn pop_segment(&mut self) {
            self.ops.push(VisitOp::Pop);
        }

        fn visit_string<'s>(&'s mut self, value: &str) -> VisitStringResult<'s, 'path> {
            self.ops.push(VisitOp::Visit(value.to_string()));
            VisitStringResult {
                might_mutate: true,
                path: &self.path,
            }
        }
    }

    #[test]
    pub fn test_hashmap_event() {
        let mut map = Map::new();
        map.insert(
            "key-a-1".to_string(),
            Value::String("value-a-1".to_string()),
        );
        map.insert(
            "key-a-2".to_string(),
            Value::String("value-b-1".to_string()),
        );
        map.insert("key-a-3".to_string(), json!(["an", "array"]));
        let mut event = HashMap::from([("key-a".to_string(), Value::Object(map))]);

        let mut visitor = Visitor {
            ops: vec![],
            path: Path::root(),
        };
        event.visit_event(&mut visitor);

        assert_eq!(
            visitor.ops,
            vec![
                VisitOp::Push(PathSegment::Field("key-a".into())),
                VisitOp::Push(PathSegment::Field("key-a-1".into())),
                VisitOp::Visit("value-a-1".into()),
                VisitOp::Pop,
                VisitOp::Push(PathSegment::Field("key-a-2".into())),
                VisitOp::Visit("value-b-1".into()),
                VisitOp::Pop,
                VisitOp::Push(PathSegment::Field("key-a-3".into())),
                VisitOp::Push(PathSegment::Index(0)),
                VisitOp::Visit("an".into()),
                VisitOp::Pop,
                VisitOp::Push(PathSegment::Index(1)),
                VisitOp::Visit("array".into()),
                VisitOp::Pop,
                VisitOp::Pop,
                VisitOp::Pop,
            ]
        );

        let mut leaf = String::new();
        event.visit_string_mut(
            &Path::from(vec![
                PathSegment::Field("key-a".into()),
                PathSegment::Field("key-a-3".into()),
                PathSegment::Index(1),
            ]),
            |s| {
                leaf = s.clone();
                true
            },
        );
        assert_eq!(leaf, "array".to_string())
    }
}
