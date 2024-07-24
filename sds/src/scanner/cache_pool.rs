use std::sync::Arc;

use regex_automata::{
    meta::Cache,
    util::pool::{Pool, PoolGuard},
};

use crate::scanner::MetaRegex;

type CachePoolFn = Box<dyn Fn() -> Vec<Cache> + Send + Sync>;
pub type CachePoolGuard<'a> = PoolGuard<'a, Vec<Cache>, CachePoolFn>;

/// This stores a set of regex caches for a specific scanner. This allows a single scan
/// operation to only have to lock / fetch a set of caches once, regardless of the
/// number of strings or rules in a single scan.
pub struct CachePool {
    pool: Pool<Vec<Cache>, CachePoolFn>,
}

impl CachePool {
    pub fn new(regexes: Arc<Vec<MetaRegex>>) -> Self {
        Self {
            pool: Pool::new(Box::new(move || {
                regexes.iter().map(|regex| regex.create_cache()).collect()
            })),
        }
    }

    pub fn get(&self) -> CachePoolGuard {
        self.pool.get()
    }
}

pub struct CachePoolBuilder {
    regexes: Vec<MetaRegex>,
}

impl Default for CachePoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CachePoolBuilder {
    pub fn new() -> Self {
        Self { regexes: vec![] }
    }

    pub fn push(&mut self, regex: MetaRegex) -> usize {
        self.regexes.push(regex);
        self.regexes.len() - 1
    }

    pub fn build(self) -> CachePool {
        CachePool::new(Arc::new(self.regexes))
    }
}
