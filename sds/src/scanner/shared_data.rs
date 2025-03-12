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

    pub fn get_mut_or_default<T: Default + Send + Sync + 'static>(&mut self) -> &mut T {
        let any = self
            .map
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(T::default()));
        any.downcast_mut().unwrap()
    }

    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        Some(self.map.get(&TypeId::of::<T>())?.downcast_ref().unwrap())
    }

    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        Some(
            self.map
                .get_mut(&TypeId::of::<T>())?
                .downcast_mut()
                .unwrap(),
        )
    }

    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(value));
    }

    pub fn insert_if_not_contains<T: Send + Sync + 'static>(
        &mut self,
        get_value: impl FnOnce() -> T,
    ) {
        self.map
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(get_value()));
    }
}
