use std::cell::{RefCell, UnsafeCell};
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use slotmap::SecondaryMap;
use treiber_stack::TreiberStack;
use crate::scanner::regex_rule::regex_store::{RegexCacheKey, SharedRegex2};
use crate::{SharedPool, SharedPoolGuard};

lazy_static! {
    static ref REGEX_CACHE_STORE: Arc<RegexCacheStore> = Arc::new(RegexCacheStore::new());
}

// pub fn take_regex_caches() -> RegexCacheGuard {
//     REGEX_CACHE_STORE.take()
// }

pub fn access_regex_caches<T>(func: impl FnOnce(&mut RegexCaches) -> T) -> T {
    let mut caches = REGEX_CACHE_STORE.take();
    let result = func(&mut caches);
    result
}

pub struct RegexCacheStore {
    free_caches: SharedPool<Box<RegexCaches>>,
}

impl RegexCacheStore {
    fn new() -> Self {
        Self {
            free_caches: SharedPool::new(|| Box::new(RegexCaches::new()))
        }
    }
    
    fn take(&self) -> SharedPoolGuard<Box<RegexCaches>> {
        self.free_caches.get()
        
        // if let Some(cache) = self.free_caches.pop() {
        //     // TODO: is this safe?
        //     cache.lock().unwrap().take().unwrap()
        //     
        // } else {
        //     Box::new(RegexCaches::new())
        // }
    }
    
    // fn insert(&self, cache: Box<RegexCaches>) {
    //     self.free_caches.push(Mutex::new(Some(cache)));
    // }
}
// 
// pub struct RegexCacheGuard {
//     // This is only `Option` so ownership can be taken in `Drop`. It will always exist
//     cache: Mutex<Option<Box<RegexCaches>>>
// }
// 
// impl Drop for RegexCacheGuard {
//     fn drop(&mut self) {
//         REGEX_CACHE_STORE.insert(self.cache.lock().unwrap().take().unwrap())
//     }
// }
// 
// impl Deref for RegexCacheGuard {
//     type Target = RegexCaches;
// 
//     fn deref(&self) -> &RegexCaches {
//         self.cache.as_ref().unwrap().deref()
//     }
// }
// 
// impl DerefMut for RegexCacheGuard {
//     fn deref_mut(&mut self) -> &mut RegexCaches {
//         self.cache.as_mut().unwrap().deref_mut()
//     }
// }

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
