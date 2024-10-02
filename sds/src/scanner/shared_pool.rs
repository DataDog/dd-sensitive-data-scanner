use regex_automata::util::pool::{Pool, PoolGuard};

type CachePoolFn<T> = Box<dyn Fn() -> T + Send + Sync>;
pub type SharedPoolGuard<'a, T> = PoolGuard<'a, T, CachePoolFn<T>>;

/// This is a simple generic wrapper around `Pool` to make it a bit easier to use
pub struct SharedPool<T> {
    pool: Pool<T, CachePoolFn<T>>,
}

impl<T: Send> SharedPool<T> {
    pub fn new(factory: impl Fn() -> T + Send + Sync + 'static) -> Self {
        Self {
            pool: Pool::new(Box::new(move || factory())),
        }
    }

    pub fn get(&self) -> SharedPoolGuard<T> {
        self.pool.get()
    }
}
