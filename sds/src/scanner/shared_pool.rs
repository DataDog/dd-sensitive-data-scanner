use std::ops::DerefMut;

use regex_automata_fork::util::pool::{Pool, PoolGuard};

type CachePoolFn<T> = Box<dyn Fn() -> T + Send + Sync>;
pub type SharedPoolGuard<'a, T, const MAX_POOL_STACKS: usize> =
    PoolGuard<'a, T, CachePoolFn<T>, MAX_POOL_STACKS>;

/// This is a simple generic wrapper around `Pool` to make it a bit easier to use
pub struct SharedPool<T> {
    pool: Box<dyn AutoStacksSizePool<T>>,
}

// AutoStacksSizePool and AutoStacksSizeGuard are used to hide away the constant generic in the Pool
pub trait AutoStacksSizePool<T>: Sync + Send {
    fn get(&self) -> Box<dyn AutoStacksSizeGuard<T> + '_>;
}

pub trait AutoStacksSizeGuard<T> {
    fn get_ref(&mut self) -> &mut T;
}

impl<'a, T: Send, const MAX_POOL_STACKS: usize> AutoStacksSizeGuard<T>
    for PoolGuard<'a, T, CachePoolFn<T>, MAX_POOL_STACKS>
{
    fn get_ref(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T: Send, const MAX_POOL_STACKS: usize> AutoStacksSizePool<T>
    for Pool<T, CachePoolFn<T>, MAX_POOL_STACKS>
{
    fn get(&self) -> Box<dyn AutoStacksSizeGuard<T> + '_> {
        Box::new(Pool::get(self))
    }
}

impl<T: Send + 'static> SharedPool<T> {
    /// Create a new shared pool with the given MAX_POOL_STACKS count.
    ///
    /// Pool stacks are a way to reduce contention on the pool for non-owners.
    /// To reduce contention as much as possible, we ideally want to have a one-to-one
    /// ratio from the number of CPUs to the number of pool stacks.
    /// This function will create a pool with the number of stacks set to the nearest power of 2
    /// greater than or equal to the given count, until 64. Anything greater than 32 will use 64.
    /// Anything less than or equal to 4 will use 4.
    ///
    /// Examples:
    ///     * new(_, 7) -> 8
    ///     * new(_, 16) -> 16
    ///     * new(_, 42) -> 64
    pub fn new(factory: CachePoolFn<T>, count: usize) -> Self {
        let pool = match count {
            x if x <= 4 => {
                Box::new(Pool::<_, _, 4>::new(factory)) as Box<dyn AutoStacksSizePool<T>>
            }
            x if x > 4 && x <= 8 => {
                Box::new(Pool::<_, _, 8>::new(factory)) as Box<dyn AutoStacksSizePool<T>>
            }
            x if x > 8 && x <= 16 => {
                Box::new(Pool::<_, _, 16>::new(factory)) as Box<dyn AutoStacksSizePool<T>>
            }
            x if x > 16 && x <= 32 => {
                Box::new(Pool::<_, _, 32>::new(factory)) as Box<dyn AutoStacksSizePool<T>>
            }
            x if x > 32 => {
                Box::new(Pool::<_, _, 64>::new(factory)) as Box<dyn AutoStacksSizePool<T>>
            }
            _ => Box::new(Pool::<_, _, 4>::new(factory)) as Box<dyn AutoStacksSizePool<T>>,
        };
        Self { pool }
    }

    pub fn get(&self) -> Box<dyn AutoStacksSizeGuard<T> + '_> {
        self.pool.get()
    }
}
