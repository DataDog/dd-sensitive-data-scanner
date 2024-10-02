use std::sync::Arc;

use regex_automata::{
    meta::Cache,
    util::pool::{Pool, PoolGuard},
};

use crate::scanner::MetaRegex;
use crate::scanner::regex_rule::RegexCaches;

type CachePoolFn<T> = Box<dyn Fn() -> T + Send + Sync>;
pub type SharedPoolGuard<'a, T> = PoolGuard<'a, T, CachePoolFn<T>>;

/// This stores a set of regex caches for a specific scanner. This allows a single scan
/// operation to only have to lock / fetch a set of caches once, regardless of the
/// number of strings or rules in a single scan.
pub struct SharedPool<T> {
    pool: Pool<T, CachePoolFn<T>>,
}

impl <T: Send> SharedPool<T> {
    pub fn new(factory: impl Fn() -> T + Send + Sync + 'static) -> Self {
        Self {
            pool: Pool::new(Box::new(move || {
                factory()
            })),
        }
    }

    pub fn get(&self) -> SharedPoolGuard<T> {
        self.pool.get()
    }
}

// pub struct CachePoolBuilder {
//     regexes: Vec<MetaRegex>,
// }
// 
// impl Default for CachePoolBuilder {
//     fn default() -> Self {
//         Self::new()
//     }
// }
// 
// impl CachePoolBuilder {
//     pub fn new() -> Self {
//         Self { regexes: vec![] }
//     }
// 
//     pub fn push(&mut self, regex: MetaRegex) -> usize {
//         self.regexes.push(regex);
//         self.regexes.len() - 1
//     }
// 
//     pub fn build(self) -> SharedPool {
//         SharedPool::new(Arc::new(self.regexes))
//     }
// }
