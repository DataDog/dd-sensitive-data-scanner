use crate::SharedPool;
use crate::scanner::regex_rule::regex_store::{RegexCacheKey, SharedRegex};
use lazy_static::lazy_static;
use regex_automata::meta::Regex as MetaRegex;
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

pub struct RegexCaches {
    map: SecondaryMap<RegexCacheKey, regex_automata::meta::Cache>,
}

impl RegexCaches {
    pub fn new() -> Self {
        Self {
            map: SecondaryMap::new(),
        }
    }

    pub fn get(&mut self, shared_regex: &SharedRegex) -> &mut regex_automata::meta::Cache {
        self.raw_get(shared_regex.cache_key, &shared_regex.regex)
    }

    pub(super) fn raw_get(
        &mut self,
        key: RegexCacheKey,
        regex: &MetaRegex,
    ) -> &mut regex_automata::meta::Cache {
        self.map
            .entry(key)
            .unwrap()
            .or_insert_with(|| regex.create_cache())
    }
}
