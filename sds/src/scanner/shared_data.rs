use ahash::AHashMap;
use std::any::{Any, TypeId};
use std::hash::Hash;

const INLINE_CAPACITY: usize = 4;

pub(crate) trait SpillMap<K, V> {
    fn with_capacity(capacity: usize) -> Self;
    #[allow(dead_code)]
    fn len(&self) -> usize;
    fn get(&self, key: &K) -> Option<&V>;
    fn get_mut(&mut self, key: &K) -> Option<&mut V>;
    fn insert(&mut self, key: K, value: V);
    fn get_or_insert_with(&mut self, key: K, make_value: impl FnOnce() -> V) -> &mut V;
}

impl<K: Eq + Hash, V> SpillMap<K, V> for AHashMap<K, V> {
    #[inline]
    fn with_capacity(capacity: usize) -> Self {
        AHashMap::with_capacity(capacity)
    }

    #[inline]
    fn len(&self) -> usize {
        std::collections::HashMap::len(self)
    }

    #[inline]
    fn get(&self, key: &K) -> Option<&V> {
        std::collections::HashMap::get(self, key)
    }

    #[inline]
    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        std::collections::HashMap::get_mut(self, key)
    }

    #[inline]
    fn insert(&mut self, key: K, value: V) {
        let _ = std::collections::HashMap::insert(self, key, value);
    }

    #[inline]
    fn get_or_insert_with(&mut self, key: K, make_value: impl FnOnce() -> V) -> &mut V {
        self.entry(key).or_insert_with(make_value)
    }
}

/// Small key-value map backed by an inline fixed-size array that spills to a heap map `S`
/// (default `AHashMap`) only when more than `N` distinct keys are inserted.
pub(crate) enum InlineSlotMap<K, V, const N: usize, S = AHashMap<K, V>> {
    Empty,
    Inline {
        entries: [Option<(K, V)>; N],
        len: usize,
    },
    Spilled(S),
}

impl<K: PartialEq, V, const N: usize, S: SpillMap<K, V>> InlineSlotMap<K, V, N, S> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self::Empty
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Inline { len, .. } => *len,
            Self::Spilled(map) => map.len(),
        }
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        match self {
            Self::Empty => None,
            Self::Inline { entries, len } => entries[..*len]
                .iter()
                .find_map(|slot| slot.as_ref().and_then(|(k, v)| (k == key).then_some(v))),
            Self::Spilled(map) => map.get(key),
        }
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self {
            Self::Empty => None,
            Self::Inline { entries, len } => entries[..*len]
                .iter_mut()
                .find_map(|slot| slot.as_mut().and_then(|(k, v)| (k == key).then_some(v))),
            Self::Spilled(map) => map.get_mut(key),
        }
    }

    #[inline]
    pub(crate) fn insert(&mut self, key: K, value: V) {
        const {
            assert!(N > 0, "InlineSlotMap inline capacity must be > 0");
        };
        match self {
            Self::Empty => {
                let mut entries = std::array::from_fn(|_| None);
                entries[0] = Some((key, value));
                *self = Self::Inline { entries, len: 1 };
            }
            Self::Inline { entries, len } => {
                for slot in &mut entries[..*len] {
                    if let Some((k, v)) = slot
                        && *k == key
                    {
                        *v = value;
                        return;
                    }
                }
                if *len < N {
                    entries[*len] = Some((key, value));
                    *len += 1;
                    return;
                }
                let mut spilled = S::with_capacity(N + 1);
                for slot in entries.iter_mut() {
                    if let Some((k, v)) = slot.take() {
                        spilled.insert(k, v);
                    }
                }
                spilled.insert(key, value);
                *self = Self::Spilled(spilled);
            }
            Self::Spilled(map) => map.insert(key, value),
        }
    }

    #[inline]
    pub(crate) fn get_or_insert_with(&mut self, key: K, make_value: impl FnOnce() -> V) -> &mut V {
        const {
            assert!(N > 0, "InlineSlotMap inline capacity must be > 0");
        };
        enum Action {
            EmptyInsert,
            InlineHit(usize),
            InlineAppend(usize),
            SpillAndAppend,
            Spilled,
        }

        let action = match self {
            Self::Empty => Action::EmptyInsert,
            Self::Inline { entries, len } => {
                if let Some(pos) = entries[..*len]
                    .iter()
                    .position(|slot| matches!(slot, Some((k, _)) if *k == key))
                {
                    Action::InlineHit(pos)
                } else if *len < N {
                    Action::InlineAppend(*len)
                } else {
                    Action::SpillAndAppend
                }
            }
            Self::Spilled(_) => Action::Spilled,
        };

        match action {
            Action::EmptyInsert => {
                let value = make_value();
                let mut entries = std::array::from_fn(|_| None);
                entries[0] = Some((key, value));
                *self = Self::Inline { entries, len: 1 };
                match self {
                    Self::Inline { entries, .. } => &mut entries[0].as_mut().unwrap().1,
                    _ => unreachable!(),
                }
            }
            Action::InlineHit(pos) => match self {
                Self::Inline { entries, .. } => &mut entries[pos].as_mut().unwrap().1,
                _ => unreachable!(),
            },
            Action::InlineAppend(idx) => {
                let value = make_value();
                match self {
                    Self::Inline { entries, len } => {
                        entries[idx] = Some((key, value));
                        *len = idx + 1;
                        &mut entries[idx].as_mut().unwrap().1
                    }
                    _ => unreachable!(),
                }
            }
            Action::SpillAndAppend => {
                // Evaluate `make_value` before taking inline entries so a panic leaves `self` intact.
                let value = make_value();
                let mut spilled = S::with_capacity(N + 1);
                if let Self::Inline { entries, .. } = self {
                    for slot in entries.iter_mut() {
                        if let Some((k, v)) = slot.take() {
                            spilled.insert(k, v);
                        }
                    }
                }
                *self = Self::Spilled(spilled);
                match self {
                    Self::Spilled(map) => map.get_or_insert_with(key, || value),
                    _ => unreachable!(),
                }
            }
            Action::Spilled => match self {
                Self::Spilled(map) => map.get_or_insert_with(key, make_value),
                _ => unreachable!(),
            },
        }
    }

    #[inline]
    pub(crate) fn insert_if_not_contains(&mut self, key: K, make_value: impl FnOnce() -> V) {
        let _ = self.get_or_insert_with(key, make_value);
    }
}

pub struct SharedData {
    // SharedData is constructed once per event and once per scanned string field, typically
    // holding 0..4 entries. An inline array avoids AHashMap's per-instance random seed atomic
    // and heap allocation on the common path.
    map: InlineSlotMap<TypeId, Box<dyn Any + Send + Sync>, INLINE_CAPACITY>,
}

impl Default for SharedData {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SharedData {
    #[inline]
    pub fn new() -> Self {
        Self {
            map: InlineSlotMap::new(),
        }
    }

    #[inline]
    pub fn get_mut_or_default<T: Default + Send + Sync + 'static>(&mut self) -> &mut T {
        let any = self
            .map
            .get_or_insert_with(TypeId::of::<T>(), || Box::new(T::default()));
        any.downcast_mut().unwrap()
    }

    #[inline]
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        Some(self.map.get(&TypeId::of::<T>())?.downcast_ref().unwrap())
    }

    #[inline]
    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        Some(
            self.map
                .get_mut(&TypeId::of::<T>())?
                .downcast_mut()
                .unwrap(),
        )
    }

    #[inline]
    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(value));
    }

    #[inline]
    pub fn insert_if_not_contains<T: Send + Sync + 'static>(
        &mut self,
        get_value: impl FnOnce() -> T,
    ) {
        self.map
            .insert_if_not_contains(TypeId::of::<T>(), || Box::new(get_value()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default, PartialEq, Eq)]
    struct TypeA(u64);
    #[derive(Debug, Default, PartialEq, Eq)]
    struct TypeB(u64);
    #[derive(Debug, Default, PartialEq, Eq)]
    struct TypeC(u64);
    #[derive(Debug, Default, PartialEq, Eq)]
    struct TypeD(u64);
    #[derive(Debug, Default, PartialEq, Eq)]
    struct TypeE(u64);
    #[derive(Debug, Default, PartialEq, Eq)]
    struct TypeF(u64);

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn shared_data_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SharedData>();
    }

    #[test]
    fn shared_data_empty_lookups_return_none() {
        let mut data = SharedData::new();
        assert_eq!(data.get::<TypeA>(), None);
        assert_eq!(data.get_mut::<TypeA>(), None);
    }

    #[test]
    fn shared_data_inline_and_spill_lifecycle() {
        let mut data = SharedData::new();
        data.insert(TypeA(1));
        data.insert(TypeB(2));
        data.insert(TypeC(3));
        data.insert(TypeD(4));
        assert!(matches!(data.map, InlineSlotMap::Inline { len: 4, .. }));

        // Overwrite at exact inline capacity should stay inline.
        data.insert(TypeB(20));
        assert!(matches!(data.map, InlineSlotMap::Inline { len: 4, .. }));
        assert_eq!(data.get::<TypeB>(), Some(&TypeB(20)));

        // 5th distinct type triggers spill.
        data.insert(TypeE(5));
        assert!(matches!(data.map, InlineSlotMap::Spilled(_)));
        assert_eq!(data.get::<TypeA>(), Some(&TypeA(1)));
        assert_eq!(data.get::<TypeB>(), Some(&TypeB(20)));
        assert_eq!(data.get::<TypeC>(), Some(&TypeC(3)));
        assert_eq!(data.get::<TypeD>(), Some(&TypeD(4)));
        assert_eq!(data.get::<TypeE>(), Some(&TypeE(5)));

        // Overwrite and insert after spill.
        data.insert(TypeE(50));
        data.insert(TypeF(6));
        assert_eq!(data.get::<TypeE>(), Some(&TypeE(50)));
        assert_eq!(data.get::<TypeF>(), Some(&TypeF(6)));

        *data.get_mut::<TypeC>().unwrap() = TypeC(30);
        assert_eq!(data.get::<TypeC>(), Some(&TypeC(30)));
    }

    #[test]
    fn shared_data_get_mut_or_default_and_insert_if_not_contains() {
        let mut data = SharedData::new();

        data.get_mut_or_default::<TypeA>().0 = 11;
        assert_eq!(data.get::<TypeA>(), Some(&TypeA(11)));
        assert_eq!(data.get_mut_or_default::<TypeA>().0, 11);

        let mut calls = 0usize;
        data.insert_if_not_contains(|| {
            calls += 1;
            TypeA(999)
        });
        assert_eq!(calls, 0);
        assert_eq!(data.get::<TypeA>(), Some(&TypeA(11)));

        data.insert_if_not_contains(|| {
            calls += 1;
            TypeB(22)
        });
        assert_eq!(calls, 1);
        assert_eq!(data.get::<TypeB>(), Some(&TypeB(22)));

        // Force spill through get_mut_or_default.
        data.get_mut_or_default::<TypeC>().0 = 33;
        data.get_mut_or_default::<TypeD>().0 = 44;
        data.get_mut_or_default::<TypeE>().0 = 55;
        assert!(matches!(data.map, InlineSlotMap::Spilled(_)));

        // Closure must still be skipped on hit after spill.
        data.insert_if_not_contains(|| {
            calls += 1;
            TypeE(999)
        });
        assert_eq!(calls, 1);
        assert_eq!(data.get::<TypeE>(), Some(&TypeE(55)));

        data.insert_if_not_contains(|| {
            calls += 1;
            TypeF(66)
        });
        assert_eq!(calls, 2);
        assert_eq!(data.get::<TypeF>(), Some(&TypeF(66)));
    }

    #[test]
    fn shared_data_drops_overwritten_and_spilled_values_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut data = SharedData::new();
            data.insert(DropCounter(Arc::clone(&drops)));
            assert_eq!(drops.load(Ordering::SeqCst), 0);

            // Overwriting inline drops the previous value immediately.
            data.insert(DropCounter(Arc::clone(&drops)));
            assert_eq!(drops.load(Ordering::SeqCst), 1);

            // Spilling moves the value without dropping it.
            data.insert(TypeA(1));
            data.insert(TypeB(2));
            data.insert(TypeC(3));
            data.insert(TypeD(4));
            assert!(matches!(data.map, InlineSlotMap::Spilled(_)));
            assert_eq!(drops.load(Ordering::SeqCst), 1);

            // Overwriting after spill drops the previous value.
            data.insert(DropCounter(Arc::clone(&drops)));
            assert_eq!(drops.load(Ordering::SeqCst), 2);
        }
        assert_eq!(drops.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn shared_data_panic_in_spill_factory_preserves_inline_entries() {
        let mut data = SharedData::new();
        data.insert(TypeA(1));
        data.insert(TypeB(2));
        data.insert(TypeC(3));
        data.insert(TypeD(4));
        assert!(matches!(data.map, InlineSlotMap::Inline { len: 4, .. }));

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            data.insert_if_not_contains::<TypeE>(|| panic!("boom during spill"));
        }));
        assert!(res.is_err());
        assert!(matches!(data.map, InlineSlotMap::Inline { len: 4, .. }));
        assert_eq!(data.get::<TypeA>(), Some(&TypeA(1)));
        assert_eq!(data.get::<TypeB>(), Some(&TypeB(2)));
        assert_eq!(data.get::<TypeC>(), Some(&TypeC(3)));
        assert_eq!(data.get::<TypeD>(), Some(&TypeD(4)));
        assert_eq!(data.get::<TypeE>(), None);

        // Subsequent spill still works cleanly.
        data.insert(TypeE(5));
        assert!(matches!(data.map, InlineSlotMap::Spilled(_)));
        assert_eq!(data.get::<TypeA>(), Some(&TypeA(1)));
        assert_eq!(data.get::<TypeE>(), Some(&TypeE(5)));
    }

    #[test]
    fn inline_slot_map_differential_randomized() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for _trial in 0..200 {
            let mut map: InlineSlotMap<u8, u32, 4> = InlineSlotMap::new();
            let mut oracle: HashMap<u8, u32> = HashMap::new();

            for _step in 0..40 {
                let op = next_u64() % 5;
                let key = (next_u64() % 12) as u8;
                let val = (next_u64() % 1000) as u32;

                match op {
                    0 => {
                        map.insert(key, val);
                        oracle.insert(key, val);
                    }
                    1 => {
                        let m = map.get_or_insert_with(key, || val);
                        let o = oracle.entry(key).or_insert(val);
                        assert_eq!(*m, *o);
                        *m = m.wrapping_add(7);
                        *o = o.wrapping_add(7);
                    }
                    2 => {
                        let mut called_map = false;
                        map.insert_if_not_contains(key, || {
                            called_map = true;
                            val
                        });
                        let mut called_oracle = false;
                        oracle.entry(key).or_insert_with(|| {
                            called_oracle = true;
                            val
                        });
                        assert_eq!(called_map, called_oracle);
                    }
                    3 => {
                        assert_eq!(map.get(&key), oracle.get(&key));
                    }
                    _ => {
                        let m = map.get_mut(&key);
                        let o = oracle.get_mut(&key);
                        assert_eq!(m.as_deref(), o.as_deref());
                        if let (Some(mv), Some(ov)) = (m, o) {
                            *mv = mv.wrapping_add(3);
                            *ov = ov.wrapping_add(3);
                        }
                    }
                }

                assert_eq!(map.len(), oracle.len());
                assert_eq!(map.is_empty(), oracle.is_empty());
                for k in 0..12u8 {
                    assert_eq!(map.get(&k), oracle.get(&k));
                }
            }
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Deterministic fixed-storage `SpillMap` used in Kani proofs so CBMC verifies every state
    /// transition of the real `InlineSlotMap` without symbolic hasher or heap-realloc blowup.
    struct LinearSpillMap<K, V> {
        entries: [Option<(K, V)>; 8],
        len: usize,
    }

    impl<K: PartialEq, V> SpillMap<K, V> for LinearSpillMap<K, V> {
        fn with_capacity(_capacity: usize) -> Self {
            Self {
                entries: [const { None }; 8],
                len: 0,
            }
        }

        fn len(&self) -> usize {
            self.len
        }

        fn get(&self, key: &K) -> Option<&V> {
            for slot in &self.entries[..self.len] {
                if let Some((k, v)) = slot
                    && k == key
                {
                    return Some(v);
                }
            }
            None
        }

        fn get_mut(&mut self, key: &K) -> Option<&mut V> {
            for slot in &mut self.entries[..self.len] {
                if let Some((k, v)) = slot
                    && k == key
                {
                    return Some(v);
                }
            }
            None
        }

        fn insert(&mut self, key: K, value: V) {
            for slot in &mut self.entries[..self.len] {
                if let Some((k, v)) = slot
                    && *k == key
                {
                    *v = value;
                    return;
                }
            }
            self.entries[self.len] = Some((key, value));
            self.len += 1;
        }

        fn get_or_insert_with(&mut self, key: K, make_value: impl FnOnce() -> V) -> &mut V {
            if let Some(pos) = self.entries[..self.len]
                .iter()
                .position(|slot| matches!(slot, Some((k, _)) if *k == key))
            {
                return &mut self.entries[pos].as_mut().unwrap().1;
            }
            let val = make_value();
            let idx = self.len;
            self.entries[idx] = Some((key, val));
            self.len += 1;
            &mut self.entries[idx].as_mut().unwrap().1
        }
    }

    const KEY_SPACE: usize = 6;

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_inline_slot_map_insert_get_overwrite_and_spill() {
        let mut map: InlineSlotMap<u8, u16, INLINE_CAPACITY, LinearSpillMap<u8, u16>> =
            InlineSlotMap::new();
        let mut oracle: [Option<u16>; KEY_SPACE] = [None; KEY_SPACE];
        let mut oracle_len: usize = 0;

        // 5 symbolic inserts/overwrites + get_mut crosses Empty -> Inline(1..=4) -> Spilled(5).
        for _ in 0..5 {
            let key: u8 = kani::any();
            kani::assume((key as usize) < KEY_SPACE);
            let val: u16 = kani::any();
            let op: u8 = kani::any();
            kani::assume(op < 2);

            if op == 0 {
                map.insert(key, val);
                if oracle[key as usize].is_none() {
                    oracle_len += 1;
                }
                oracle[key as usize] = Some(val);
            } else {
                let delta: u16 = kani::any();
                match (map.get_mut(&key), &mut oracle[key as usize]) {
                    (Some(mv), Some(ov)) => {
                        assert_eq!(*mv, *ov);
                        *mv = mv.wrapping_add(delta);
                        *ov = ov.wrapping_add(delta);
                    }
                    (None, None) => {}
                    _ => panic!("get_mut presence mismatch"),
                }
            }

            assert_eq!(map.len(), oracle_len);
            assert_eq!(map.is_empty(), oracle_len == 0);
        }

        let probe: u8 = kani::any();
        kani::assume((probe as usize) < KEY_SPACE);
        assert_eq!(map.get(&probe).copied(), oracle[probe as usize]);
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_inline_slot_map_get_or_insert_with_and_closure_skip() {
        let mut map: InlineSlotMap<u8, u16, INLINE_CAPACITY, LinearSpillMap<u8, u16>> =
            InlineSlotMap::new();
        let mut oracle: [Option<u16>; KEY_SPACE] = [None; KEY_SPACE];
        let mut oracle_len: usize = 0;

        for _ in 0..5 {
            let key: u8 = kani::any();
            kani::assume((key as usize) < KEY_SPACE);
            let val: u16 = kani::any();
            let use_if_not_contains: bool = kani::any();

            let mut called = false;
            if use_if_not_contains {
                map.insert_if_not_contains(key, || {
                    called = true;
                    val
                });
                let expected_called = oracle[key as usize].is_none();
                assert_eq!(called, expected_called);
                if expected_called {
                    oracle[key as usize] = Some(val);
                    oracle_len += 1;
                }
            } else {
                let delta: u16 = kani::any();
                let slot = map.get_or_insert_with(key, || {
                    called = true;
                    val
                });
                let expected_called = oracle[key as usize].is_none();
                assert_eq!(called, expected_called);
                if expected_called {
                    oracle[key as usize] = Some(val);
                    oracle_len += 1;
                }
                assert_eq!(*slot, oracle[key as usize].unwrap());
                *slot = slot.wrapping_add(delta);
                oracle[key as usize] = Some(oracle[key as usize].unwrap().wrapping_add(delta));
            }

            assert_eq!(map.len(), oracle_len);
        }

        let probe: u8 = kani::any();
        kani::assume((probe as usize) < KEY_SPACE);
        assert_eq!(map.get(&probe).copied(), oracle[probe as usize]);
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn kani_inline_slot_map_capacity_one_spill_boundary() {
        let mut map: InlineSlotMap<u8, u16, 1, LinearSpillMap<u8, u16>> = InlineSlotMap::new();
        let mut oracle: [Option<u16>; 3] = [None; 3];
        let mut oracle_len: usize = 0;

        for _ in 0..3 {
            let key: u8 = kani::any();
            kani::assume(key < 3);
            let val: u16 = kani::any();
            let use_entry: bool = kani::any();

            if use_entry {
                let mut called = false;
                let slot = map.get_or_insert_with(key, || {
                    called = true;
                    val
                });
                let absent = oracle[key as usize].is_none();
                assert_eq!(called, absent);
                if absent {
                    oracle[key as usize] = Some(val);
                    oracle_len += 1;
                }
                assert_eq!(*slot, oracle[key as usize].unwrap());
            } else {
                map.insert(key, val);
                if oracle[key as usize].is_none() {
                    oracle_len += 1;
                }
                oracle[key as usize] = Some(val);
            }

            if oracle_len == 1 {
                assert!(matches!(map, InlineSlotMap::Inline { len: 1, .. }));
            } else if oracle_len > 1 {
                assert!(matches!(map, InlineSlotMap::Spilled(_)));
            }
            assert_eq!(map.len(), oracle_len);
        }

        let probe: u8 = kani::any();
        kani::assume(probe < 3);
        assert_eq!(map.get(&probe).copied(), oracle[probe as usize]);
    }
}
