use crate::stats::GLOBAL_STATS;
use ahash::AHashMap;
use lazy_static::lazy_static;
use regex_automata::meta::{Cache, Regex as MetaRegex};
use slotmap::{new_key_type, SlotMap};
use std::ops::Deref;
use std::sync::Weak;
use std::sync::{Arc, Mutex};

struct WeakSharedRegex {
    regex: Weak<MetaRegex>,
    // number of bytes used for the cache. Just used for metrics.
    cache_size: usize,
}

#[derive(Debug)]
pub struct SharedRegex {
    pub(super) regex: Arc<MetaRegex>,
    pub(super) cache_key: RegexCacheKey,
}

impl Deref for SharedRegex {
    type Target = MetaRegex;

    fn deref(&self) -> &Self::Target {
        self.regex.deref()
    }
}

pub fn get_memoized_regex<T>(
    pattern: &str,
    regex_factory: impl FnOnce(&str) -> Result<regex_automata::meta::Regex, T>,
) -> Result<SharedRegex, T> {
    get_memoized_regex_with_custom_store(pattern, regex_factory, &REGEX_STORE)
}

fn get_memoized_regex_with_custom_store<T>(
    pattern: &str,
    regex_factory: impl FnOnce(&str) -> Result<regex_automata::meta::Regex, T>,
    store: &Mutex<RegexStore>,
) -> Result<SharedRegex, T> {
    {
        let regex_store = store.lock().unwrap();
        if let Some(exiting_regex) = regex_store.get(pattern) {
            return Ok(exiting_regex);
        }
    }

    // Create the new regex after the RegexStore lock is released, since this can be slow
    let regex = regex_factory(pattern)?;

    let mut regex_store = store.lock().unwrap();
    Ok(regex_store.insert(pattern, regex))
}

// A GC of the regex store happens every N insertions
// This is needed to occasionally clean out Weak references that have been dropped.
const GC_FREQUENCY: u64 = 1_000;

lazy_static! {
    static ref REGEX_STORE: Arc<Mutex<RegexStore>> = Arc::new(Mutex::new(RegexStore::new()));
}
new_key_type! { pub struct RegexCacheKey; }

struct RegexStore {
    pattern_index: AHashMap<String, RegexCacheKey>,
    key_map: SlotMap<RegexCacheKey, WeakSharedRegex>,
    // used to decide when to GC. Counts up to `GC_FREQUENCY` and is reset to 0 when a GC happens
    gc_counter: u64,
}

impl RegexStore {
    pub fn new() -> Self {
        Self {
            pattern_index: AHashMap::new(),
            key_map: SlotMap::with_key(),
            gc_counter: 0,
        }
    }

    /// Cleans up any configuration no longer used in Scanners. Should be called periodically.
    fn gc(&mut self) {
        self.gc_counter = 0;
        self.pattern_index.retain(|_, cache_key| {
            if self.key_map.get(*cache_key).unwrap().regex.strong_count() == 0 {
                if let Some(old_regex) = self.key_map.remove(*cache_key) {
                    GLOBAL_STATS.add_total_regex_cache(-(old_regex.cache_size as i64));
                }
                false
            } else {
                true
            }
        });
        GLOBAL_STATS.set_total_regexes(self.key_map.len());
    }

    /// Check if a regex for this pattern already exists, and returns a copy if it does
    pub fn get(&self, pattern: &str) -> Option<SharedRegex> {
        self.pattern_index.get(pattern).and_then(|cache_key| {
            self.key_map
                .get(*cache_key)
                .and_then(|x| x.regex.upgrade())
                .map(|regex| SharedRegex {
                    regex,
                    cache_key: *cache_key,
                })
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        debug_assert_eq!(self.pattern_index.len(), self.key_map.len());
        self.key_map.len()
    }

    /// Inserts a new rule into the cache. The "memoized" rule is returned and should be
    /// used instead of the one passed in. This ensures that if there were duplicates of
    /// a rule being created at the same time, only one is kept.
    pub fn insert(&mut self, pattern: &str, regex: MetaRegex) -> SharedRegex {
        self.gc_counter += 1;
        if self.gc_counter >= GC_FREQUENCY {
            self.gc();
        }
        if let Some(existing_regex) = self.get(pattern) {
            existing_regex
        } else {
            let shared_regex = Arc::new(regex);

            let regex_cache = shared_regex.create_cache();
            let cache_key = self.key_map.insert(WeakSharedRegex {
                regex: Arc::downgrade(&shared_regex),
                cache_size: regex_cache.memory_usage() + std::mem::size_of::<Cache>(),
            });
            if let Some(old_cache_key) = self.pattern_index.insert(pattern.to_owned(), cache_key) {
                // cleanup old value (which must be a "dead" reference since `get` returned None)
                if let Some(weak_ref) = self.key_map.remove(old_cache_key) {
                    GLOBAL_STATS.add_total_regex_cache(-(weak_ref.cache_size as i64));
                    debug_assert!(weak_ref.regex.strong_count() == 0)
                }
            }

            GLOBAL_STATS.set_total_regexes(self.key_map.len());

            SharedRegex {
                regex: shared_regex,
                cache_key,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::scanner::regex_rule::regex_store::{
        get_memoized_regex_with_custom_store, RegexStore, GC_FREQUENCY,
    };
    use regex_automata::meta::Regex;
    use std::sync::Mutex;

    #[test]
    fn dropped_regexes_should_be_removed_from_global_store() {
        let store = Mutex::new(RegexStore::new());

        let regex = get_memoized_regex_with_custom_store("test", Regex::new, &store).unwrap();

        assert_eq!(store.lock().unwrap().len(), 1);

        drop(regex);

        // force an early GC
        store.lock().unwrap().gc();

        assert_eq!(store.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_automatic_gc() {
        let store = Mutex::new(RegexStore::new());

        let regex = get_memoized_regex_with_custom_store("test", Regex::new, &store).unwrap();
        drop(regex);

        // insert enough new patterns to trigger a GC
        for i in 0..(GC_FREQUENCY - 1) {
            let regex =
                get_memoized_regex_with_custom_store(&format!("test-{}", i), Regex::new, &store)
                    .unwrap();
            drop(regex)
        }
        // The insertion that triggered the GC is itself not cleaned up yet, but everything else is
        assert_eq!(store.lock().unwrap().len(), 1);
    }
}
