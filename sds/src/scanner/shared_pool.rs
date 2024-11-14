use std::ops::DerefMut;

use regex_automata::util::pool::{Pool, PoolGuard};

type CachePoolFn<T> = Box<dyn Fn() -> T + Send + Sync>;
pub type SharedPoolGuard<'a, T, const MAX_POOL_STACKS: usize> =
    PoolGuard<'a, T, CachePoolFn<T>, MAX_POOL_STACKS>;

/// This is a simple generic wrapper around `Pool` to make it a bit easier to use
pub struct SharedPool<T> {
    // pool: Pool<T, CachePoolFn<T>, MAX_POOL_STACKS>,
    pool: Box<dyn MyPoolTrait<T>>,
}

pub trait MyPoolTrait<T>: Sync + Send {
    fn get(&self) -> Box<dyn MyPoolGuardTrait<T> + '_>;
}

pub trait MyPoolGuardTrait<T> {
    //TODO fill
    fn get_ref(&mut self) -> &mut T;
}

impl<'a, T: Send, const MAX_POOL_STACKS: usize> MyPoolGuardTrait<T>
    for PoolGuard<'a, T, CachePoolFn<T>, MAX_POOL_STACKS>
{
    fn get_ref(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T: Send, const MAX_POOL_STACKS: usize> MyPoolTrait<T>
    for Pool<T, CachePoolFn<T>, MAX_POOL_STACKS>
{
    fn get(&self) -> Box<dyn MyPoolGuardTrait<T> + '_> {
        Box::new(Pool::get(self))
    }
}

impl<T: Send + 'static> SharedPool<T> {
    pub fn new(factory: CachePoolFn<T>, count: usize) -> Self {
        let pool = match count {
            8 => Box::new(Pool::<_, _, 8>::new(factory)) as Box<dyn MyPoolTrait<T>>,
            16 => Box::new(Pool::<_, _, 16>::new(factory)) as Box<dyn MyPoolTrait<T>>,
            32 => Box::new(Pool::<_, _, 32>::new(factory)) as Box<dyn MyPoolTrait<T>>,
            _ => Box::new(Pool::<_, _, 4>::new(factory)) as Box<dyn MyPoolTrait<T>>,
        };
        Self { pool }
    }

    pub fn get(&self) -> Box<dyn MyPoolGuardTrait<T> + '_> {
        self.pool.get()
    }
}
