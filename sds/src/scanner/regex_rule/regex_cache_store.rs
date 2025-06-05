use crate::scanner::regex_rule::regex_store::{RegexCacheKey, SharedRegex};
use crate::stats::GLOBAL_STATS;
use crate::SharedPool;
use lazy_static::lazy_static;
use regex_automata::meta;
use regex_automata::meta::{Cache, Regex as MetaRegex};
use slotmap::SecondaryMap;
use std::sync::Arc;

extern crate num_cpus;

lazy_static! {
    static ref REGEX_CACHE_STORE: Arc<SharedPool<Box<RegexCaches>>> = Arc::new(SharedPool::new(
        Box::new(|| Box::new(RegexCaches::new())),
        num_cpus::get()
    ));
}

pub fn access_regex_caches<T>(func: impl FnOnce(&mut RegexCaches) -> T) -> T {
    // This function isn't strictly necessary, but it makes it easier to change the implementation
    // later
    let mut caches = REGEX_CACHE_STORE.get();
    func(caches.get_ref())
}

pub enum CacheHandle<'a> {
    Borrowed(&'a mut Cache),
    Owned(Box<Cache>),
}

impl<'a> AsMut<Cache> for CacheHandle<'a> {
    fn as_mut(&mut self) -> &mut Cache {
        match self {
            CacheHandle::Borrowed(x) => x,
            CacheHandle::Owned(x) => x,
        }
    }
}

pub struct RegexCaches {
    map: SecondaryMap<RegexCacheKey, Cache>,
}

impl RegexCaches {
    pub fn new() -> Self {
        Self {
            map: SecondaryMap::new(),
        }
    }

    pub fn get(&mut self, shared_regex: &SharedRegex) -> CacheHandle {
        if let Some(x) = self.raw_get(shared_regex.cache_key, &shared_regex.regex) {
            CacheHandle::Borrowed(x)
        } else {
            // This _should_ never happen, but it somehow does. A root cause / fix has not been identified yet. A
            // one-off cache is created. This will work but can be slow if it happens often.
            // This is tracked by a new metric since otherwise this would no longer be visible.
            GLOBAL_STATS.regex_store_errors.increment(1);
            CacheHandle::Owned(Box::new(shared_regex.create_cache()))
        }
    }

    pub(super) fn raw_get(
        &mut self,
        key: RegexCacheKey,
        regex: &MetaRegex,
    ) -> Option<&mut meta::Cache> {
        self.map
            .entry(key)
            .map(|x| x.or_insert_with(|| regex.create_cache()))
    }
}
