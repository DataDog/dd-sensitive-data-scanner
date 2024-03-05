use nom::{
    Compare, CompareResult, FindSubstring, InputIter, InputLength, InputTake, Needed, Offset,
    Slice, UnspecializedInput,
};
use std::ops::{RangeFrom, RangeTo};
use std::str::{CharIndices, Chars};

/// This implements a custom nom input type that also tracks the recursion depth, which
/// allows limiting the recursion depth to prevent stack overflows from deep recursion.

#[derive(Copy, Clone, Debug)]
pub struct Input<'a> {
    pub value: &'a str,
    pub depth: usize,
}

impl<'a> InputLength for Input<'a> {
    fn input_len(&self) -> usize {
        self.value.len()
    }
}

impl<'a> InputTake for Input<'a> {
    fn take(&self, count: usize) -> Self {
        Self {
            value: self.value.take(count),
            depth: self.depth,
        }
    }

    fn take_split(&self, count: usize) -> (Self, Self) {
        let (a, b) = self.value.take_split(count);
        (
            Self {
                value: a,
                depth: self.depth,
            },
            Self {
                value: b,
                depth: self.depth,
            },
        )
    }
}

impl<'a> InputIter for Input<'a> {
    type Item = char;
    type Iter = CharIndices<'a>;
    type IterElem = Chars<'a>;

    fn iter_indices(&self) -> Self::Iter {
        self.value.iter_indices()
    }

    fn iter_elements(&self) -> Self::IterElem {
        self.value.iter_elements()
    }

    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.value.position(predicate)
    }

    fn slice_index(&self, count: usize) -> Result<usize, Needed> {
        self.value.slice_index(count)
    }
}

impl<'a> UnspecializedInput for Input<'a> {
    // Automatically implements InputTakeAtPosition and Compare<Self>
}

// This is implementing comparison directly to &str instead of Self so functions like `tag`
// can directly use strings instead of having to make up an arbitrary `Input`
impl<'a> Compare<&'a str> for Input<'a> {
    fn compare(&self, t: &'a str) -> CompareResult {
        self.value.compare(t)
    }

    fn compare_no_case(&self, t: &'a str) -> CompareResult {
        self.value.compare_no_case(t)
    }
}

impl<'a> From<(&'a str, usize)> for Input<'a> {
    fn from(value: (&'a str, usize)) -> Self {
        Self {
            value: value.0,
            depth: value.1,
        }
    }
}

impl<'a> Slice<RangeFrom<usize>> for Input<'a> {
    fn slice(&self, range: RangeFrom<usize>) -> Self {
        Self {
            value: self.value.slice(range),
            depth: self.depth,
        }
    }
}

impl<'a> Slice<RangeTo<usize>> for Input<'a> {
    fn slice(&self, range: RangeTo<usize>) -> Self {
        Self {
            value: self.value.slice(range),
            depth: self.depth,
        }
    }
}

impl<'a> Offset for Input<'a> {
    fn offset(&self, second: &Self) -> usize {
        self.value.offset(second.value)
    }
}

impl<'a> FindSubstring<&'a str> for Input<'a> {
    fn find_substring(&self, substr: &'a str) -> Option<usize> {
        self.value.find_substring(substr)
    }
}
