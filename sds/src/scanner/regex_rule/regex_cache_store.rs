use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use slotmap::SecondaryMap;
use crate::scanner::regex_rule::regex_store::{RegexCacheKey, SharedRegex2};

lazy_static! {
    static ref REGEX_CACHE_STORE: Arc<Mutex<RegexCacheStore>> = Arc::new(Mutex::new(RegexCacheStore::new()));
}

pub fn take_regex_caches() -> RegexCacheGuard {
    REGEX_CACHE_STORE.lock().unwrap().take()
}

pub struct RegexCacheStore {
    free_caches: Vec<Box<RegexCaches>>
}

impl RegexCacheStore {
    fn new() -> Self {
        Self {
            free_caches: vec![]
        }
    }
    
    fn take(&mut self) -> RegexCacheGuard {
        let cache = if let Some(cache) = self.free_caches.pop() {
            cache
        } else {
            Box::new(RegexCaches::new())
        };
        RegexCacheGuard {
            cache: Some(cache)
        }
    }
    
    fn insert(&mut self, cache: Box<RegexCaches>) {
        self.free_caches.push(cache);
    }
}

pub struct RegexCacheGuard {
    // This is only `Option` so ownership can be taken in `Drop`. It will always exist
    cache: Option<Box<RegexCaches>>
}

impl Drop for RegexCacheGuard {
    fn drop(&mut self) {
        REGEX_CACHE_STORE.lock().unwrap().insert(self.cache.take().unwrap())
    }
}

impl Deref for RegexCacheGuard {
    type Target = RegexCaches;

    fn deref(&self) -> &RegexCaches {
        self.cache.as_ref().unwrap().deref()
    }
}

impl DerefMut for RegexCacheGuard {
    fn deref_mut(&mut self) -> &mut RegexCaches {
        self.cache.as_mut().unwrap().deref_mut()
    }
}

pub struct RegexCaches {
    map: SecondaryMap<RegexCacheKey, regex_automata::meta::Cache>
}

impl RegexCaches {
    pub fn new() -> Self {
        Self {
            map: SecondaryMap::new()
        }
    }
    
    pub fn get(&mut self, shared_regex: &SharedRegex2) -> &mut regex_automata::meta::Cache {
        self.map.entry(shared_regex.cache_key).unwrap()
            .or_insert_with(|| shared_regex.regex.create_cache())
    }
}
