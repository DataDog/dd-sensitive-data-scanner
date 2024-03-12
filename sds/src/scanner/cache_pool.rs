use std::sync::Arc;

use regex_automata::{
    meta::Cache,
    util::pool::{Pool, PoolGuard},
};

use super::CompiledRule;

type CachePoolFn = Box<dyn Fn() -> Vec<Cache> + Send + Sync>;
pub type CachePoolGuard<'a> = PoolGuard<'a, Vec<Cache>, CachePoolFn>;

/// This stores a set of regex caches for a specific scanner. This allows a single scan
/// operation to only have to lock / fetch a set of caches once, regardless of the
/// number of strings or rules in a single scan.
pub struct CachePool {
    pool: Pool<Vec<Cache>, CachePoolFn>,
}

impl CachePool {
    pub fn new(rules: Arc<Vec<CompiledRule>>) -> Self {
        Self {
            pool: Pool::new(Box::new(move || {
                rules.iter().map(|rule| rule.regex.create_cache()).collect()
            })),
        }
    }

    pub fn get(&self) -> CachePoolGuard {
        self.pool.get()
    }
}
