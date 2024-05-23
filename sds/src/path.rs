use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};

use crate::proximity_keywords::{MULTI_WORD_KEYWORDS_LINK_CHARS, UNIFIED_LINK_CHAR};
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

impl<'a> Path<'a> {
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

    pub fn absolute_path(&self) -> String {
        self.segments
            .iter()
            .filter_map(|segment| match segment {
                PathSegment::Field(field) => Some(field.to_string().to_ascii_lowercase()),
                _ => None,
            })
            .collect::<Vec<String>>()
            .join(UNIFIED_LINK_CHAR.to_string().as_str())
            .chars()
            .map(|c| {
                if MULTI_WORD_KEYWORDS_LINK_CHARS.contains(&c) {
                    return UNIFIED_LINK_CHAR;
                }
                c
            })
            .collect()
    }
}

impl<'a> PathSegment<'a> {
    pub fn into_static(&self) -> PathSegment<'static> {
        match self {
            PathSegment::Field(cow) => PathSegment::Field(Cow::Owned(cow.as_ref().to_owned())),
            PathSegment::Index(i) => PathSegment::Index(*i),
        }
    }
}

impl<'a> Debug for Path<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

// Note: This format isn't great, some indices / fields can collide, and fields aren't escaped.
// It's kept like this to match the existing "logs-backend" behavior.
impl<'a> Display for Path<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, segment) in self.segments.iter().enumerate() {
            match segment {
                PathSegment::Field(field) => {
                    if i != 0 {
                        write!(f, ".")?;
                    }
                    write!(f, "{}", field)?;
                }
                PathSegment::Index(i) => {
                    write!(f, "[{}]", i)?;
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
    fn test_absolute_path() {
        assert_eq!(
            Path::from(vec!["hello".into(), 0.into(), "world".into()]).absolute_path(),
            "hello.world"
        );
        assert_eq!(
            Path::from(vec!["hello".into(), 1.into(), "CHICKEN".into(), 2.into()]).absolute_path(),
            "hello.chicken"
        );
        assert_eq!(
            Path::from(vec![
                "hello_world-of".into(),
                1.into(),
                "CHICKEN".into(),
                2.into(),
            ])
            .absolute_path(),
            "hello.world.of.chicken"
        );
    }
}
