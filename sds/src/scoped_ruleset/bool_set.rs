pub(crate) const INLINE_WORDS: usize = 4;
pub(crate) const BITS_PER_WORD: usize = u64::BITS as usize;
pub(crate) const INLINE_BOOL_CAPACITY: usize = 128;

enum BoolStorage {
    Inline {
        flags: [bool; INLINE_BOOL_CAPACITY],
        len: u8,
    },
    Heap(Vec<bool>),
}

/// Keeps track of multiple contiguous boolean flags and resets all of them efficiently.
///
/// Stores up to 128 flags inline on the stack (`[bool; 128]`) and spills to `Vec<bool>` above
/// that, keeping byte-indexed access free of bit-packing read-modify-write stalls while avoiding
/// per-event heap allocation on typical rule counts.
pub struct BoolSet {
    storage: BoolStorage,
}

impl BoolSet {
    #[inline]
    pub fn new(num_rules: usize) -> Self {
        let storage = if num_rules <= INLINE_BOOL_CAPACITY {
            BoolStorage::Inline {
                flags: [false; INLINE_BOOL_CAPACITY],
                len: num_rules as u8,
            }
        } else {
            BoolStorage::Heap(vec![false; num_rules])
        };
        Self { storage }
    }

    #[inline]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [bool] {
        match &mut self.storage {
            BoolStorage::Inline { flags, len } => &mut flags[..usize::from(*len)],
            BoolStorage::Heap(flags) => flags.as_mut_slice(),
        }
    }

    #[allow(dead_code)]
    #[inline]
    pub fn get_and_set(&mut self, index: usize) -> bool {
        let slot = &mut self.as_mut_slice()[index];
        let prev = *slot;
        *slot = true;
        prev
    }

    #[inline]
    pub fn reset(&mut self) {
        self.as_mut_slice().fill(false);
    }
}

#[inline]
pub(crate) fn contains_bit(words: &[u64], index: usize) -> bool {
    let word_idx = index / BITS_PER_WORD;
    words
        .get(word_idx)
        .is_some_and(|&word| (word & (1u64 << (index % BITS_PER_WORD))) != 0)
}

pub(crate) fn set_bit(words: &mut Vec<u64>, index: usize) {
    let word_idx = index / BITS_PER_WORD;
    if words.len() <= word_idx {
        words.resize(word_idx + 1, 0);
    }
    words[word_idx] |= 1u64 << (index % BITS_PER_WORD);
}

pub(crate) fn clear_bit(words: &mut Vec<u64>, index: usize) {
    let word_idx = index / BITS_PER_WORD;
    if let Some(word) = words.get_mut(word_idx) {
        *word &= !(1u64 << (index % BITS_PER_WORD));
        // Trim trailing zero words so `words.is_empty()` remains exact for "no bits set".
        while words.last() == Some(&0) {
            words.pop();
        }
    }
}

/// Reusable bitset buffer for combining active exclusion sets along a path.
/// Keeps unions up to 256 rules inline without heap allocation and spills to `Vec<u64>` above.
pub(crate) enum InlineBitBuffer {
    Empty,
    Inline {
        words: [u64; INLINE_WORDS],
        len: usize,
    },
    Heap(Vec<u64>),
}

impl InlineBitBuffer {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self::Empty
    }

    pub(crate) fn set_union_of<S: AsRef<[u64]>>(&mut self, sets: &[S]) {
        let max_len = sets.iter().map(|set| set.as_ref().len()).max().unwrap_or(0);
        if max_len == 0 {
            match self {
                Self::Empty => {}
                Self::Inline { len, .. } => *len = 0,
                Self::Heap(words) => words.clear(),
            }
            return;
        }

        let dst: &mut [u64] = if max_len <= INLINE_WORDS {
            match self {
                Self::Empty => {
                    *self = Self::Inline {
                        words: [0; INLINE_WORDS],
                        len: max_len,
                    };
                    match self {
                        Self::Inline { words, .. } => &mut words[..max_len],
                        _ => unreachable!(),
                    }
                }
                Self::Inline { words, len } => {
                    words[..max_len].fill(0);
                    *len = max_len;
                    &mut words[..max_len]
                }
                Self::Heap(words) => {
                    words.clear();
                    words.resize(max_len, 0);
                    words.as_mut_slice()
                }
            }
        } else {
            match self {
                Self::Heap(words) => {
                    words.clear();
                    words.resize(max_len, 0);
                    words.as_mut_slice()
                }
                Self::Empty | Self::Inline { .. } => {
                    *self = Self::Heap(vec![0; max_len]);
                    match self {
                        Self::Heap(words) => words.as_mut_slice(),
                        _ => unreachable!(),
                    }
                }
            }
        };

        for set in sets {
            for (dst_word, &src_word) in dst.iter_mut().zip(set.as_ref().iter()) {
                *dst_word |= src_word;
            }
        }
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[u64] {
        match self {
            Self::Empty => &[],
            Self::Inline { words, len } => &words[..*len],
            Self::Heap(words) => words.as_slice(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_set_storage_mode_at_boundary() {
        assert!(matches!(
            BoolSet::new(0).storage,
            BoolStorage::Inline { len: 0, .. }
        ));
        assert!(matches!(
            BoolSet::new(1).storage,
            BoolStorage::Inline { len: 1, .. }
        ));
        assert!(matches!(
            BoolSet::new(127).storage,
            BoolStorage::Inline { len: 127, .. }
        ));
        assert!(matches!(
            BoolSet::new(128).storage,
            BoolStorage::Inline { len: 128, .. }
        ));
        assert!(matches!(BoolSet::new(129).storage, BoolStorage::Heap(_)));
        assert!(matches!(BoolSet::new(256).storage, BoolStorage::Heap(_)));
        assert!(matches!(BoolSet::new(513).storage, BoolStorage::Heap(_)));
    }

    #[test]
    fn bool_set_boundary_sizes_match_vec_oracle() {
        for &num_rules in &[
            0usize, 1, 4, 5, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257, 320, 511, 512, 513,
            1024,
        ] {
            let mut set = BoolSet::new(num_rules);
            let mut oracle = vec![false; num_rules];

            for round in 0..3 {
                for (i, slot) in oracle.iter_mut().enumerate() {
                    let expected = *slot;
                    *slot = true;
                    assert_eq!(
                        set.get_and_set(i),
                        expected,
                        "mismatch on first pass num_rules={num_rules} round={round} i={i}"
                    );
                }
                for i in (0..num_rules).rev() {
                    assert!(
                        set.get_and_set(i),
                        "expected true on repeat num_rules={num_rules} round={round} i={i}"
                    );
                }
                set.reset();
                oracle.fill(false);
            }
        }
    }

    /// Verbatim `origin/main` `BoolSet` implementation used as the differential oracle.
    struct MainBoolSet {
        rule_used: Vec<bool>,
    }

    impl MainBoolSet {
        fn new(num_rules: usize) -> Self {
            Self {
                rule_used: vec![false; num_rules],
            }
        }

        fn get_and_set(&mut self, index: usize) -> bool {
            let result = self.rule_used[index];
            self.rule_used[index] = true;
            result
        }

        fn reset(&mut self) {
            self.rule_used.fill(false);
        }
    }

    #[test]
    fn bool_set_differential_vs_verbatim_main_100k_ops() {
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let sizes = [
            1usize, 2, 16, 63, 64, 65, 127, 128, 129, 130, 255, 256, 257, 300, 512, 513,
        ];
        let ops_per_size = 100_000 / sizes.len() + 1;

        for &num_rules in &sizes {
            let mut set = BoolSet::new(num_rules);
            let mut oracle = MainBoolSet::new(num_rules);

            for _ in 0..ops_per_size {
                if next_u64().is_multiple_of(40) {
                    set.reset();
                    oracle.reset();
                } else {
                    let idx = (next_u64() as usize) % num_rules;
                    assert_eq!(set.get_and_set(idx), oracle.get_and_set(idx));
                }
            }
            assert_eq!(set.as_mut_slice(), oracle.rule_used.as_slice());
        }
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn bool_set_inline_oob_panics() {
        let mut set = BoolSet::new(10);
        let _ = set.get_and_set(10);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn bool_set_zero_len_oob_panics() {
        let mut set = BoolSet::new(0);
        let _ = set.get_and_set(0);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn bool_set_heap_oob_panics() {
        let mut set = BoolSet::new(129);
        let _ = set.get_and_set(129);
    }

    #[test]
    fn bit_helpers_trim_trailing_zeros_and_handle_large_indices() {
        let mut words = Vec::new();
        assert!(!contains_bit(&words, 0));
        assert!(!contains_bit(&words, usize::MAX));

        for &idx in &[0usize, 63, 64, 255, 256, 257, 511] {
            set_bit(&mut words, idx);
            assert!(contains_bit(&words, idx));
        }

        clear_bit(&mut words, 511);
        assert!(!contains_bit(&words, 511));
        assert_eq!(words.len(), 5);

        for &idx in &[257usize, 256, 255, 64, 63, 0] {
            clear_bit(&mut words, idx);
            assert!(!contains_bit(&words, idx));
        }
        assert!(words.is_empty());
    }

    #[test]
    fn inline_bit_buffer_transitions_across_inline_and_heap() {
        let mut buf = InlineBitBuffer::new();
        assert!(buf.as_slice().is_empty());

        let mut s1 = Vec::new();
        set_bit(&mut s1, 1);
        set_bit(&mut s1, 64);
        let mut s2 = Vec::new();
        set_bit(&mut s2, 255);
        buf.set_union_of(&[&s1, &s2]);
        assert!(matches!(buf, InlineBitBuffer::Inline { len: 4, .. }));
        assert!(contains_bit(buf.as_slice(), 1));
        assert!(contains_bit(buf.as_slice(), 64));
        assert!(contains_bit(buf.as_slice(), 255));
        assert!(!contains_bit(buf.as_slice(), 256));

        // Spill above 256 rules.
        let mut s3 = Vec::new();
        set_bit(&mut s3, 300);
        buf.set_union_of(&[&s1, &s3]);
        assert!(matches!(buf, InlineBitBuffer::Heap(_)));
        assert!(contains_bit(buf.as_slice(), 1));
        assert!(contains_bit(buf.as_slice(), 300));
        assert!(!contains_bit(buf.as_slice(), 255));

        // Shrink back to smaller union without stale upper words leaking.
        buf.set_union_of(&[&s1]);
        assert!(contains_bit(buf.as_slice(), 1));
        assert!(contains_bit(buf.as_slice(), 64));
        assert!(!contains_bit(buf.as_slice(), 300));

        // Empty union clears everything.
        let empty: [&Vec<u64>; 0] = [];
        buf.set_union_of(&empty);
        assert!(buf.as_slice().is_empty());
    }

    #[test]
    fn inline_bit_buffer_and_bit_helpers_differential_50k_ops() {
        let mut seed: u64 = 0xabcd_ef01_2345_6789;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let mut buf = InlineBitBuffer::new();
        let mut total_ops = 0usize;

        while total_ops < 50_000 {
            let max_bit = match next_u64() % 4 {
                0 => 64usize,
                1 => 256usize,
                2 => 260usize,
                _ => 512usize,
            };
            let num_sets = (next_u64() % 6) as usize;
            let mut sets: Vec<Vec<u64>> = Vec::with_capacity(num_sets);
            let mut expected = vec![false; max_bit];

            for _ in 0..num_sets {
                let mut words = Vec::new();
                let mut set_oracle = vec![false; max_bit];
                let num_ops = (next_u64() % 20) as usize;
                for _ in 0..num_ops {
                    let bit = (next_u64() as usize) % max_bit;
                    if next_u64().is_multiple_of(3) {
                        clear_bit(&mut words, bit);
                        set_oracle[bit] = false;
                    } else {
                        set_bit(&mut words, bit);
                        set_oracle[bit] = true;
                    }
                    assert_eq!(contains_bit(&words, bit), set_oracle[bit]);
                    assert!(words.last() != Some(&0));
                    total_ops += 1;
                }
                for (bit, &is_set) in set_oracle.iter().enumerate() {
                    if is_set {
                        expected[bit] = true;
                    }
                }
                sets.push(words);
            }

            buf.set_union_of(&sets);
            total_ops += 1;
            for (bit, &exp) in expected.iter().enumerate() {
                assert_eq!(contains_bit(buf.as_slice(), bit), exp, "bit {bit}");
            }
            assert!(!contains_bit(buf.as_slice(), max_bit));
        }
    }
}
