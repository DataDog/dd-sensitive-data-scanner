use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};

use crate::proximity_keywords::{
    BypassStandardizePathResult, UNIFIED_LINK_CHAR, should_bypass_standardize_path,
    standardize_path_chars,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Path<'a> {
    pub segments: Vec<PathSegment<'a>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "type", content = "value")]
pub enum PathSegment<'a> {
    Field(Cow<'a, str>),
    Index(usize),
}

#[inline]
fn is_already_sanitized_segment(field: &str) -> bool {
    // Only ASCII uppercase letters and non-dot link chars (`-`, `_`, ` `, `/`)
    // can be rewritten or split by `standardize_path_chars` + ASCII lowercasing.
    field
        .bytes()
        .all(|b| !matches!(b, b'A'..=b'Z' | b'-' | b'_' | b' ' | b'/'))
}

impl Path<'_> {
    /// An empty path - pointing to the root.
    pub fn root() -> Self {
        Self { segments: vec![] }
    }

    /// Converts and path segment references into Owned strings so the lifetime can be static.
    pub fn into_static(&self) -> Path<'static> {
        Path {
            segments: self.segments.iter().map(PathSegment::into_static).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn starts_with(&self, prefix: &Path) -> bool {
        if prefix.len() > self.len() {
            // the prefix is longer than the path
            return false;
        }

        // ensure all segments of `prefix` match self
        for (a, b) in prefix.segments.iter().zip(self.segments.iter()) {
            if a != b {
                return false;
            }
        }
        true
    }

    pub(crate) fn size_segments_only(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| {
                if let PathSegment::Field(field) = segment {
                    return field.len();
                }
                0
            })
            .sum()
    }

    /// Returns the sanitized path without copying when the path is already in
    /// sanitized form (empty, or a single already-sanitized field segment).
    #[inline]
    pub(crate) fn as_already_sanitized(&self) -> Option<&str> {
        match self.segments.as_slice() {
            [] => Some(""),
            [PathSegment::Field(field)] if is_already_sanitized_segment(field) => {
                Some(field.as_ref())
            }
            _ => None,
        }
    }

    pub(crate) fn sanitize_into(&self, sanitized_path: &mut String) {
        for (i, segment) in self.segments.iter().enumerate() {
            if let PathSegment::Field(field) = segment {
                if i != 0 {
                    sanitized_path.push(UNIFIED_LINK_CHAR);
                }

                if is_already_sanitized_segment(field) {
                    sanitized_path.push_str(field);
                } else if should_bypass_standardize_path(field)
                    != BypassStandardizePathResult::NoBypass
                {
                    // All characters are ASCII letters (all-lowercase already matched above),
                    // so every byte lowers directly without a temporary String allocation.
                    sanitized_path.reserve(field.len());
                    for b in field.bytes() {
                        sanitized_path.push(b.to_ascii_lowercase() as char);
                    }
                } else {
                    standardize_path_chars(field, |c| {
                        sanitized_path.push(c.to_ascii_lowercase());
                    });
                }
            }
        }
    }

    pub fn sanitize(&self) -> String {
        let size_segments = self.size_segments_only();
        let mut sanitized_path = String::with_capacity(size_segments + size_segments / 2);
        self.sanitize_into(&mut sanitized_path);
        sanitized_path
    }
}

impl<'a> PathSegment<'a> {
    pub fn into_static(&self) -> PathSegment<'static> {
        match self {
            PathSegment::Field(cow) => PathSegment::Field(Cow::Owned(cow.as_ref().to_owned())),
            PathSegment::Index(i) => PathSegment::Index(*i),
        }
    }

    pub fn is_index(&self) -> bool {
        matches!(self, PathSegment::Index(_))
    }

    pub fn length(&self) -> usize {
        if let PathSegment::Field(field) = self {
            field.len()
        } else {
            0
        }
    }

    pub fn sanitize(&self) -> Option<Cow<'a, str>> {
        if let PathSegment::Field(field) = self {
            if is_already_sanitized_segment(field) {
                return Some(field.clone());
            }
            match should_bypass_standardize_path(field) {
                BypassStandardizePathResult::BypassAndAllLowercase => Some(field.clone()),
                BypassStandardizePathResult::BypassAndAllUppercase => {
                    Some(Cow::Owned(field.to_ascii_lowercase()))
                }
                BypassStandardizePathResult::NoBypass => {
                    let mut sanitized_segment = String::with_capacity(self.length() + 1);
                    standardize_path_chars(field, |c| {
                        sanitized_segment.push(c.to_ascii_lowercase());
                    });
                    Some(Cow::Owned(sanitized_segment))
                }
            }
        } else {
            None
        }
    }
}

impl Debug for Path<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

// Note: This format isn't great, some indices / fields can collide, and fields aren't escaped.
// It's kept like this to match the existing "logs-backend" behavior.
impl Display for Path<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, segment) in self.segments.iter().enumerate() {
            match segment {
                PathSegment::Field(field) => {
                    if i != 0 {
                        write!(f, ".")?;
                    }
                    write!(f, "{field}")?;
                }
                PathSegment::Index(i) => {
                    write!(f, "[{i}]")?;
                }
            }
        }
        Ok(())
    }
}

impl<'a> From<Vec<PathSegment<'a>>> for Path<'a> {
    fn from(segments: Vec<PathSegment<'a>>) -> Self {
        Self { segments }
    }
}

impl<'a> From<&'a str> for PathSegment<'a> {
    fn from(value: &'a str) -> Self {
        Self::Field(Cow::Borrowed(value))
    }
}

impl From<usize> for PathSegment<'static> {
    fn from(value: usize) -> Self {
        PathSegment::Index(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proximity_keywords::UNIFIED_LINK_STR;

    #[test]
    fn test_starts_with() {
        let foo = Path::from(vec!["foo".into()]);
        let foo_bar = Path::from(vec!["foo".into(), "bar".into()]);
        let array_foo = Path::from(vec![0.into(), "foo".into()]);

        assert!(foo_bar.starts_with(&foo));
        assert!(!foo.starts_with(&foo_bar));
        assert!(foo.starts_with(&foo));
        assert!(!foo.starts_with(&array_foo));
        assert!(!array_foo.starts_with(&foo));
    }

    #[test]
    fn test_sanitize_segments() {
        assert_eq!(
            Path::from(vec!["hello".into(), 0.into(), "world".into()])
                .segments
                .iter()
                .filter_map(|segment| { segment.sanitize() })
                .collect::<Vec<_>>()
                .join(UNIFIED_LINK_STR),
            "hello.world"
        );
        assert_eq!(
            Path::from(vec!["hello".into(), 1.into(), "CHICKEN".into(), 2.into()])
                .segments
                .iter()
                .filter_map(|segment| { segment.sanitize() })
                .collect::<Vec<_>>()
                .join(UNIFIED_LINK_STR),
            "hello.chicken"
        );
        assert_eq!(
            Path::from(vec![
                "hello_world-of".into(),
                1.into(),
                "CHICKEN".into(),
                2.into(),
            ])
            .segments
            .iter()
            .filter_map(|segment| { segment.sanitize() })
            .collect::<Vec<_>>()
            .join(UNIFIED_LINK_STR),
            "hello.world.of.chicken"
        );

        assert_eq!(
            Path::from(vec!["hello_world-of-".into(), "/chickens_/".into()])
                .segments
                .iter()
                .filter_map(|segment| { segment.sanitize() })
                .collect::<Vec<_>>()
                .join(UNIFIED_LINK_STR),
            "hello.world.of-./chickens./"
        );
    }

    #[test]
    fn test_sanitize_path() {
        assert_eq!(
            Path::from(vec!["hello".into(), 0.into(), "world".into()]).sanitize(),
            "hello.world"
        );
        assert_eq!(
            Path::from(vec!["hello".into(), 1.into(), "CHICKEN".into(), 2.into()]).sanitize(),
            "hello.chicken"
        );
        assert_eq!(
            Path::from(vec![
                "hello_world-of".into(),
                1.into(),
                "CHICKEN".into(),
                2.into(),
            ])
            .sanitize(),
            "hello.world.of.chicken"
        );

        assert_eq!(
            Path::from(vec!["hello_world-of-".into(), "/chickens_/".into()]).sanitize(),
            "hello.world.of-./chickens./"
        );
        assert_eq!(
            Path::from(vec!["helloChicken".into()]).sanitize(),
            "hello.chicken"
        );
    }

    #[test]
    fn test_size() {
        assert_eq!(
            Path::from(vec!["hello".into(), 0.into(), "world".into()]).size_segments_only(),
            10
        );
        assert_eq!(
            Path::from(vec!["".into(), 0.into(), "path✅".into()]).size_segments_only(),
            7
        );
    }

    #[test]
    fn test_sanitize_fast_paths_match_reference() {
        fn reference_sanitize(path: &Path) -> String {
            let mut out = String::new();
            for (i, segment) in path.segments.iter().enumerate() {
                if let PathSegment::Field(field) = segment {
                    if i != 0 {
                        out.push(UNIFIED_LINK_CHAR);
                    }
                    if should_bypass_standardize_path(field)
                        != BypassStandardizePathResult::NoBypass
                    {
                        out.push_str(&field.to_ascii_lowercase());
                    } else {
                        standardize_path_chars(field, |c| {
                            out.push(c.to_ascii_lowercase());
                        });
                    }
                }
            }
            out
        }

        let cases: Vec<Path> = vec![
            Path::root(),
            Path::from(vec!["".into()]),
            Path::from(vec!["message".into()]),
            Path::from(vec!["field1".into()]),
            Path::from(vec!["0".into()]),
            Path::from(vec!["http.url".into()]),
            Path::from(vec!["http..url".into()]),
            Path::from(vec![".leading".into()]),
            Path::from(vec!["trailing.".into()]),
            Path::from(vec!["CHICKEN".into()]),
            Path::from(vec!["helloChicken".into()]),
            Path::from(vec!["hello-world".into()]),
            Path::from(vec!["hello_world".into()]),
            Path::from(vec!["hello world".into()]),
            Path::from(vec!["hello/world".into()]),
            Path::from(vec!["-".into()]),
            Path::from(vec!["_".into()]),
            Path::from(vec![".".into()]),
            Path::from(vec!["A".into()]),
            Path::from(vec!["café".into()]),
            Path::from(vec!["path✅".into()]),
            Path::from(vec!["caféCamel".into()]),
            Path::from(vec![0.into()]),
            Path::from(vec![0.into(), 1.into()]),
            Path::from(vec![0.into(), "hello".into()]),
            Path::from(vec!["hello".into(), 0.into()]),
            Path::from(vec![
                "service-7".into(),
                0.into(),
                "UPPER".into(),
                "camelCase".into(),
                "plain123".into(),
            ]),
        ];

        let mut reusable_buf = String::from("stale-contents");
        for path in &cases {
            let expected = reference_sanitize(path);
            assert_eq!(path.sanitize(), expected, "sanitize mismatch for {path:?}");

            if let Some(borrowed) = path.as_already_sanitized() {
                assert_eq!(
                    borrowed, expected,
                    "as_already_sanitized mismatch for {path:?}"
                );
            }

            reusable_buf.clear();
            path.sanitize_into(&mut reusable_buf);
            assert_eq!(
                reusable_buf, expected,
                "sanitize_into mismatch for {path:?}"
            );
        }

        // Single already-sanitized field segments should borrow without allocating.
        assert_eq!(
            Path::from(vec!["message".into()]).as_already_sanitized(),
            Some("message")
        );
        assert_eq!(
            Path::from(vec!["field1.sub".into()]).as_already_sanitized(),
            Some("field1.sub")
        );
        assert_eq!(
            Path::from(vec!["CHICKEN".into()]).as_already_sanitized(),
            None
        );
        assert_eq!(
            Path::from(vec![0.into(), "hello".into()]).as_already_sanitized(),
            None
        );
        assert!(matches!(
            PathSegment::from("field1").sanitize(),
            Some(Cow::Borrowed("field1"))
        ));
    }
}
