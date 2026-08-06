use crate::SharedPool;
use crate::scanner::regex_rule::regex_store::{RegexCacheKey, SharedRegex};
use lazy_static::lazy_static;
use regex_automata::meta::Regex as MetaRegex;
use slotmap::SecondaryMap;
use std::sync::{Arc, RwLock};
extern crate num_cpus;

fn new_regex_cache_pool() -> Arc<SharedPool<Box<RegexCaches>>> {
    Arc::new(SharedPool::new(
        Box::new(|| Box::new(RegexCaches::new())),
        num_cpus::get(),
    ))
}

lazy_static! {
    // `RwLock` lets `reset_regex_caches` swap in a fresh pool, dropping every thread's caches.
    static ref REGEX_CACHE_STORE: RwLock<Arc<SharedPool<Box<RegexCaches>>>> =
        RwLock::new(new_regex_cache_pool());
}

pub fn access_regex_caches<T>(func: impl FnOnce(&mut RegexCaches) -> T) -> T {
    // Clone the `Arc` under a short read lock so scanning holds no lock; a concurrent
    // `reset_regex_caches` keeps this in-flight pool alive via the clone.
    let pool = REGEX_CACHE_STORE.read().unwrap().clone();
    let mut caches = pool.get();
    func(caches.get_ref())
}

/// Swaps in a fresh pool, dropping every thread's cached scratch. In-flight scans keep the
/// old pool alive via their `Arc` clone; caches are recreated on the next scan.
pub fn reset_regex_caches() {
    *REGEX_CACHE_STORE.write().unwrap() = new_regex_cache_pool();
}

pub struct RegexCaches {
    map: SecondaryMap<RegexCacheKey, RegexCacheValue>,
}

pub struct RegexCacheValue {
    pub cache: regex_automata::meta::Cache,
    pub captures: regex_automata::util::captures::Captures,
}

impl RegexCaches {
    pub fn new() -> Self {
        Self {
            map: SecondaryMap::new(),
        }
    }

    pub fn get(&mut self, shared_regex: &SharedRegex) -> &mut RegexCacheValue {
        self.raw_get(shared_regex.cache_key, &shared_regex.regex)
    }

    pub(super) fn raw_get(
        &mut self,
        key: RegexCacheKey,
        regex: &MetaRegex,
    ) -> &mut RegexCacheValue {
        self.map
            .entry(key)
            .unwrap()
            .or_insert_with(|| RegexCacheValue {
                cache: regex.create_cache(),
                captures: regex.create_captures(),
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::scanner::regex_rule::regex_store::get_memoized_regex;
    use regex_automata::meta::Regex;

    #[test]
    fn reset_swaps_pool_and_still_serves_caches() {
        let shared = get_memoized_regex("unique-reset-pattern", Regex::new).unwrap();
        access_regex_caches(|caches| {
            let _ = caches.get(&shared);
        });

        // Hold the old pool so its allocation can't be reused (flaky ptr compare), then
        // confirm reset installs a different pool.
        let old_pool = REGEX_CACHE_STORE.read().unwrap().clone();
        reset_regex_caches();
        let new_pool = REGEX_CACHE_STORE.read().unwrap().clone();
        assert!(!Arc::ptr_eq(&old_pool, &new_pool));

        // Fresh pool recreates caches on next access.
        access_regex_caches(|caches| {
            let _ = caches.get(&shared);
        });
    }
}
