use ahash::AHashMap;
use std::sync::{Arc, Mutex};
use std::sync::Weak;
use lazy_static::lazy_static;
use regex_automata::meta::Regex as MetaRegex;
use slotmap::{new_key_type, SlotMap};

pub type SharedRegex = Arc<MetaRegex>;
type WeakSharedRegex = Weak<MetaRegex>;

// A GC of the regex store happens every N insertions
// This is needed to occasionally clean out Weak references that have been dropped.
const GC_FREQUENCY: u64 = 1_000;

lazy_static! {
    pub static ref REGEX_STORE: Arc<Mutex<RegexStore>> = Arc::new(Mutex::new(RegexStore::new()));
}
new_key_type! { pub struct RegexCacheKey; }

pub struct RegexStore {
    pattern_index: AHashMap<String, RegexCacheKey>,
    key_map: SlotMap<RegexCacheKey, WeakSharedRegex>,
    gc_counter: u64
}

impl RegexStore {
    pub fn new() -> Self {
        Self {
            pattern_index: AHashMap::new(),
            key_map: SlotMap::with_key(),
            gc_counter: 0
        }
    }

    /// Cleans up any configuration no longer used in Scanners. Should be called periodically.
    fn gc(&mut self) {
        self.gc_counter = 0;
        self.pattern_index.retain(|pattern, cache_key|{
           if self.key_map.get(*cache_key).unwrap().strong_count() == 0 {
               self.key_map.remove(*cache_key);
               false
           } else {
               true
           }
        });
    }

    /// Check if a regex for this pattern already exists, and returns a copy if it does
    pub fn get(&self, pattern: &str) -> Option<SharedRegex> {
        self.pattern_index.get(pattern)
            .and_then(|k|self.key_map.get(*k))
            .and_then(Weak::upgrade)
    }

    /// Inserts a new rule into the cache. The "memoized" rule is returned and should be
    /// used instead of the one passed in. This ensures that if there were duplicates of
    /// a rule being created at the same time, only one is kept.
    pub fn insert(
        &mut self,
        pattern: &str,
        regex: MetaRegex,
    ) -> SharedRegex {
        self.gc_counter += 1;
        if self.gc_counter >= GC_FREQUENCY {
            self.gc();
        }
        if let Some(existing_regex) = self.get(pattern) {
            existing_regex
        } else {
            let shared_regex = Arc::new(regex);
            let cache_key = self.key_map.insert(Arc::downgrade(&shared_regex));
            if let Some(old_cache_key) = self.pattern_index.insert(pattern.to_owned(), cache_key) {
                // cleanup old value (which must be a "dead" reference)
                if let Some(weak_ref) = self.key_map.remove(old_cache_key) {
                    debug_assert!(weak_ref.strong_count() == 0)
                }
            }
            shared_regex
        }
    }
}