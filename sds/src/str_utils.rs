/// Efficiently find the index of the start of the previous UTF-8 character
pub fn get_previous_char_index(input: &str, mut index: usize) -> Option<usize> {
    while index > 0 {
        index -= 1;
        if input.is_char_boundary(index) {
            return Some(index);
        }
    }
    None
}

/// Efficiently find the index of the start of the next UTF-8 character
pub fn get_next_char_index(input: &str, mut index: usize) -> Option<usize> {
    while index < input.len() {
        index += 1;
        if input.is_char_boundary(index) {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod test {
    use super::{get_next_char_index, get_previous_char_index};

    #[test]
    fn test_next_prev_char() {
        let test_cases = vec![
            ("abcd", 0, Some(1), None),
            ("abcd", 1, Some(2), Some(0)),
            ("abcd", 4, None, Some(3)),
            ("ÀñôΑβω", 2, Some(4), Some(0)),
            ("ÀñôΑβω", 0, Some(2), None),
            ("ÀñôΑβω", 12, None, Some(10)),
        ];

        for (input, start, expected_next, expected_prev) in test_cases {
            let next = get_next_char_index(input, start);
            let prev = get_previous_char_index(input, start);
            assert_eq!(next, expected_next);
            assert_eq!(prev, expected_prev);
        }
    }
}
