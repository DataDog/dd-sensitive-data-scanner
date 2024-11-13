use regex_automata::util::pool::{Pool, PoolGuard};

type CachePoolFn<T> = Box<dyn Fn() -> T + Send + Sync>;
pub type SharedPoolGuard<'a, T, const MAX_POOL_STACKS: usize> =
    PoolGuard<'a, T, CachePoolFn<T>, MAX_POOL_STACKS>;

/// This is a simple generic wrapper around `Pool` to make it a bit easier to use
pub struct SharedPool<T, const MAX_POOL_STACKS: usize> {
    pool: Pool<T, CachePoolFn<T>, MAX_POOL_STACKS>,
}

impl<T: Send, const MAX_POOL_STACKS: usize> SharedPool<T, MAX_POOL_STACKS> {
    pub fn new(factory: impl Fn() -> T + Send + Sync + 'static) -> Self {
        Self {
            pool: Pool::<_, _, MAX_POOL_STACKS>::new(Box::new(factory)),
        }
    }

    pub fn get(&self) -> SharedPoolGuard<T, MAX_POOL_STACKS> {
        self.pool.get()
    }
}
