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

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_bool_set_inline_equivalence() {
        const MAX_N: usize = 8;
        let num_rules: usize = kani::any();
        kani::assume(num_rules <= MAX_N);

        let mut set = BoolSet::new(num_rules);
        assert!(matches!(set.storage, BoolStorage::Inline { .. }));
        assert_eq!(set.as_mut_slice().len(), num_rules);

        let mut oracle = [false; MAX_N];

        for _ in 0..4 {
            let do_reset: bool = kani::any();
            if do_reset || num_rules == 0 {
                set.reset();
                oracle = [false; MAX_N];
            } else {
                let idx: usize = kani::any();
                kani::assume(idx < num_rules);
                let expected = oracle[idx];
                oracle[idx] = true;
                assert_eq!(set.get_and_set(idx), expected);
            }
        }

        if num_rules > 0 {
            let probe: usize = kani::any();
            kani::assume(probe < num_rules);
            assert_eq!(set.as_mut_slice()[probe], oracle[probe]);
        }
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_bool_set_heap_boundary_equivalence() {
        let num_rules: usize = kani::any();
        kani::assume(num_rules > INLINE_BOOL_CAPACITY && num_rules <= INLINE_BOOL_CAPACITY + 4);

        let mut set = BoolSet::new(num_rules);
        assert!(matches!(set.storage, BoolStorage::Heap(_)));
        assert_eq!(set.as_mut_slice().len(), num_rules);

        let i0: usize = kani::any();
        let i1: usize = kani::any();
        let i2: usize = kani::any();
        kani::assume(i0 < num_rules && i1 < num_rules && i2 < num_rules);

        assert!(!set.get_and_set(i0));
        assert_eq!(set.get_and_set(i1), i1 == i0);
        assert_eq!(set.get_and_set(i2), i2 == i0 || i2 == i1);

        let probe: usize = kani::any();
        kani::assume(probe < num_rules);
        assert_eq!(
            set.as_mut_slice()[probe],
            probe == i0 || probe == i1 || probe == i2
        );
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_bool_set_boundary_and_heap_reset() {
        // Part 1: exact max inline capacity (128) does not truncate `len as u8` and indexes 0..128.
        let mut inline_max = BoolSet::new(INLINE_BOOL_CAPACITY);
        assert!(matches!(
            inline_max.storage,
            BoolStorage::Inline { len: 128, .. }
        ));
        assert_eq!(inline_max.as_mut_slice().len(), INLINE_BOOL_CAPACITY);
        let a: usize = kani::any();
        let b: usize = kani::any();
        kani::assume(a < INLINE_BOOL_CAPACITY && b < INLINE_BOOL_CAPACITY);
        assert!(!inline_max.get_and_set(a));
        assert_eq!(inline_max.get_and_set(b), b == a);
        assert!(inline_max.get_and_set(INLINE_BOOL_CAPACITY - 1) == (a == 127 || b == 127));

        // Part 2: Heap variant `as_mut_slice`, `get_and_set`, and `reset` clear every slot.
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 6);
        let mut heap_set = BoolSet {
            storage: BoolStorage::Heap(vec![false; n]),
        };
        let i0: usize = kani::any();
        let i1: usize = kani::any();
        kani::assume(i0 < n && i1 < n);
        assert!(!heap_set.get_and_set(i0));
        assert_eq!(heap_set.get_and_set(i1), i1 == i0);

        heap_set.reset();

        let probe: usize = kani::any();
        kani::assume(probe < n);
        assert!(!heap_set.as_mut_slice()[probe]);
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_bit_helpers_set_clear_and_trim_two_words() {
        // Exhaustively verify `contains_bit`, `set_bit`, and `clear_bit` (including trailing-zero
        // word trimming) across word 0 (0..64) and word 1 (64..128) for all symbolic bit indices.
        const MAX_BITS: usize = 2 * BITS_PER_WORD;
        let i0: usize = kani::any();
        let probe: usize = kani::any();
        kani::assume(i0 < MAX_BITS && probe < MAX_BITS);

        let mut words: Vec<u64> = Vec::new();
        assert!(!contains_bit(&words, probe));

        set_bit(&mut words, i0);
        assert!(words.last() != Some(&0));
        assert!(!words.is_empty());
        assert_eq!(contains_bit(&words, probe), probe == i0);

        clear_bit(&mut words, i0);
        assert!(words.is_empty());
        assert!(!contains_bit(&words, probe));
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(7)]
    fn kani_bit_helpers_partial_trim_across_256_boundary() {
        // Verify `clear_bit` trims trailing zero words across the 256-bit inline boundary (word 4
        // down to word 0) while preserving any arbitrary non-zero 64-bit pattern in word 0, and
        // `contains_bit` stays exact for all bit positions in word 0 and word 4.
        let lo_word: u64 = kani::any();
        kani::assume(lo_word != 0);
        let b_hi: usize = kani::any();
        let probe_b: usize = kani::any();
        kani::assume(b_hi < BITS_PER_WORD && probe_b < BITS_PER_WORD);
        let hi = 4 * BITS_PER_WORD + b_hi;

        let mut words: Vec<u64> = vec![lo_word, 0, 0, 0, 1u64 << b_hi];
        assert!(contains_bit(&words, hi));
        assert_eq!(
            contains_bit(&words, probe_b),
            (lo_word & (1u64 << probe_b)) != 0
        );

        // Clearing `hi` must trim words 4, 3, 2, 1 so `words.len() == 1` and `lo_word` is intact.
        clear_bit(&mut words, hi);
        assert_eq!(words.len(), 1);
        assert_eq!(words[0], lo_word);
        assert!(words.last() != Some(&0));
        assert!(!contains_bit(&words, hi));
        assert_eq!(
            contains_bit(&words, probe_b),
            (lo_word & (1u64 << probe_b)) != 0
        );
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn kani_inline_bit_buffer_empty_to_inline() {
        // Exhaustively verify all 2^64 bit patterns per word for Empty -> Inline(4)
        // combining unequal lengths (2 words | 4 words).
        let a0: [u64; 2] = kani::any();
        let a1: [u64; INLINE_WORDS] = kani::any();
        let probe_word: usize = kani::any();
        kani::assume(probe_word < INLINE_WORDS);

        let mut buf = InlineBitBuffer::new();
        assert!(buf.as_slice().is_empty());

        buf.set_union_of(&[&a0[..], &a1[..]]);
        assert!(matches!(buf, InlineBitBuffer::Inline { len: 4, .. }));
        let w0 = if probe_word < 2 { a0[probe_word] } else { 0 };
        assert_eq!(buf.as_slice()[probe_word], w0 | a1[probe_word]);
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn kani_inline_bit_buffer_inline_reuse_and_clear() {
        // Exhaustively verify Inline(4) -> Inline(2) re-zeroes words 0..2 and hides words 2..4
        // for arbitrary prior dirty words.
        let dirty: [u64; INLINE_WORDS] = kani::any();
        let fresh: [u64; 2] = kani::any();
        let probe_word: usize = kani::any();
        kani::assume(probe_word < INLINE_WORDS);

        let mut buf = InlineBitBuffer::Inline {
            words: dirty,
            len: INLINE_WORDS,
        };

        buf.set_union_of(&[&fresh[..]]);
        assert!(matches!(buf, InlineBitBuffer::Inline { len: 2, .. }));
        let expected_after_shrink = if probe_word < 2 { fresh[probe_word] } else { 0 };
        assert_eq!(
            buf.as_slice().get(probe_word).copied().unwrap_or(0),
            expected_after_shrink
        );
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_inline_bit_buffer_inline_to_empty_clear() {
        let dirty: [u64; INLINE_WORDS] = kani::any();
        let mut buf = InlineBitBuffer::Inline {
            words: dirty,
            len: INLINE_WORDS,
        };
        let empty: [&[u64]; 0] = [];
        buf.set_union_of(&empty);
        assert!(buf.as_slice().is_empty());
        kani::cover!(true, "post-assertion conclusion reachable");
    }

    #[kani::proof]
    #[kani::unwind(7)]
    fn kani_inline_bit_buffer_union_heap_spill() {
        // Exhaustively verify arbitrary 64-bit word patterns across Inline -> Heap (5 words = 320
        // rules), Heap -> Heap (overwrite without stale bits), Heap -> smaller (2 words), and
        // Heap -> Empty.
        const MAX_WORDS: usize = INLINE_WORDS + 1;
        let init: [u64; INLINE_WORDS] = kani::any();
        let a0: [u64; MAX_WORDS] = kani::any();
        let a1: [u64; MAX_WORDS] = kani::any();
        let fresh: [u64; 2] = kani::any();
        let probe_word: usize = kani::any();
        kani::assume(probe_word < MAX_WORDS);

        let mut buf = InlineBitBuffer::new();
        // Start Inline(4), then spill Inline -> Heap(5).
        buf.set_union_of(&[&init[..INLINE_WORDS]]);
        assert!(matches!(buf, InlineBitBuffer::Inline { len: 4, .. }));

        buf.set_union_of(&[&a0[..3], &a1[..MAX_WORDS]]);
        assert!(matches!(buf, InlineBitBuffer::Heap(_)));
        assert_eq!(buf.as_slice().len(), MAX_WORDS);

        let w0 = if probe_word < 3 { a0[probe_word] } else { 0 };
        assert_eq!(buf.as_slice()[probe_word], w0 | a1[probe_word]);

        // Shrink from 5-word Heap back to 2 words: no stale upper words may leak!
        buf.set_union_of(&[&fresh[..2]]);
        assert_eq!(buf.as_slice().len(), 2);
        let expected_after_shrink = if probe_word < 2 { fresh[probe_word] } else { 0 };
        assert_eq!(
            buf.as_slice().get(probe_word).copied().unwrap_or(0),
            expected_after_shrink
        );

        // Grow back on existing Heap buffer to 5 words: old words 2..5 must be zeroed!
        buf.set_union_of(&[&a0[..MAX_WORDS]]);
        assert_eq!(buf.as_slice().len(), MAX_WORDS);
        assert_eq!(buf.as_slice()[probe_word], a0[probe_word]);

        // Empty union must clear all words.
        let empty: [&[u64]; 0] = [];
        buf.set_union_of(&empty);
        assert!(buf.as_slice().is_empty());
        kani::cover!(true, "post-assertion conclusion reachable");
    }
}
