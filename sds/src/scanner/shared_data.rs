use ahash::AHashMap;
use std::any::{Any, TypeId};

pub struct SharedData {
    map: AHashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl SharedData {
    pub fn new() -> Self {
        Self {
            map: AHashMap::new(),
        }
    }

    pub fn get_mut<T: Default + Send + Sync + 'static>(&mut self) -> &mut T {
        let any = self
            .map
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(T::default()));
        any.downcast_mut().unwrap()
    }

    pub fn get<T: Default + Send + Sync + 'static>(&self) -> Option<&T> {
        Some(self.map.get(&TypeId::of::<T>())?.downcast_ref().unwrap())
    }
}
