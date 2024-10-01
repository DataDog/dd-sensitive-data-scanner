use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;

lazy_static! {
    static ref REGEX_CACHE_STORE: Arc<Mutex<RegexCacheStore>> = Arc::new(Mutex::new(RegexCacheStore::new()));
}

pub fn get_regex_cache() -> RegexCacheGuard {
    REGEX_CACHE_STORE.lock().unwrap().take()
}

pub struct RegexCacheStore {
    free_caches: Vec<Box<RegexCache>>
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
            Box::new(RegexCache::new())
        };
        RegexCacheGuard {
            cache: Some(cache)
        }
    }
    
    fn insert(&mut self, cache: Box<RegexCache>) {
        self.free_caches.push(cache);
    }
}

pub struct RegexCacheGuard {
    // This is only `Option` so ownership can be taken in `Drop`. It will always exist
    cache: Option<Box<RegexCache>>
}

impl Drop for RegexCacheGuard {
    fn drop(&mut self) {
        REGEX_CACHE_STORE.lock().unwrap().insert(self.cache.take().unwrap())
    }
}

impl Deref for RegexCacheGuard {
    type Target = RegexCache;

    fn deref(&self) -> &RegexCache {
        self.cache.as_ref().unwrap().deref()
    }
}

impl DerefMut for RegexCacheGuard {
    fn deref_mut(&mut self) -> &mut RegexCache {
        self.cache.as_mut().unwrap().deref_mut()
    }
}

pub struct RegexCache {
    
}

impl RegexCache {
    pub fn new() -> Self {
        Self {
            
        }
    }
}
