/// Specifies how indices are calculated for rule matches
pub trait Encoding: Sized {
    type Index: Sized + 'static;
    type IndexShift: Sized;

    fn zero_index() -> Self::Index;
    fn zero_shift() -> Self::IndexShift;

    fn get_index(value: &Self::Index, utf8_index: usize) -> usize;
    fn get_shift(value: &Self::IndexShift, utf8_shift: isize) -> isize;

    /// A iterator of indices. You are given the UTF-8 indices, and need to calculate the "custom" indices.
    /// The UTF-8 indices are guaranteed to be sorted in ascending order by the start index.
    fn calculate_indices<'a>(
        content: &str,
        match_visitor: impl Iterator<Item = EncodeIndices<'a, Self>>,
    );

    /// Calculates the change of an index from replacing `before` with `after`
    fn adjust_shift(shift: &mut Self::IndexShift, before: &str, after: &str);
}

pub struct Utf8Encoding;

impl Encoding for Utf8Encoding {
    type Index = ();
    type IndexShift = ();

    fn zero_index() -> Self::Index { /* do nothing */
    }
    fn zero_shift() -> Self::IndexShift { /* do nothing */
    }

    fn get_index(_value: &Self::Index, utf8_index: usize) -> usize {
        utf8_index
    }

    fn get_shift(_value: &Self::IndexShift, utf8_shift: isize) -> isize {
        utf8_shift
    }

    fn calculate_indices<'a>(
        _content: &str,
        _match_visitor: impl Iterator<Item = EncodeIndices<'a, Self>>,
    ) {
        // do nothing, indices are already correct
    }

    fn adjust_shift(_shift: &mut Self::IndexShift, _before: &str, _after: &str) {
        // do nothing
    }
}

pub struct EncodeIndices<'a, E: Encoding> {
    // Input
    pub utf8_start: usize,
    pub utf8_end: usize,

    // Output
    pub custom_start: &'a mut E::Index,
    pub custom_end: &'a mut E::Index,
}
