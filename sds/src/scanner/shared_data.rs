use std::any::{Any, TypeId};

/// Data of one type per entry. A scan uses very few types, and `new` runs once per string, so a
/// linear search over a vector is faster than a hash map, and an empty vector costs nothing.
pub struct SharedData {
    entries: Vec<(TypeId, Box<dyn Any + Send + Sync>)>,
}

impl SharedData {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn position(&self, type_id: TypeId) -> Option<usize> {
        self.entries.iter().position(|(id, _)| *id == type_id)
    }

    pub fn get_mut_or_default<T: Default + Send + Sync + 'static>(&mut self) -> &mut T {
        let type_id = TypeId::of::<T>();
        let index = self.position(type_id).unwrap_or_else(|| {
            self.entries.push((type_id, Box::new(T::default())));
            self.entries.len() - 1
        });
        self.entries[index].1.downcast_mut().unwrap()
    }

    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        let index = self.position(TypeId::of::<T>())?;
        Some(self.entries[index].1.downcast_ref().unwrap())
    }

    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        let index = self.position(TypeId::of::<T>())?;
        Some(self.entries[index].1.downcast_mut().unwrap())
    }

    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) {
        let type_id = TypeId::of::<T>();
        match self.position(type_id) {
            Some(index) => self.entries[index].1 = Box::new(value),
            None => self.entries.push((type_id, Box::new(value))),
        }
    }

    pub fn insert_if_not_contains<T: Send + Sync + 'static>(
        &mut self,
        get_value: impl FnOnce() -> T,
    ) {
        let type_id = TypeId::of::<T>();
        if self.position(type_id).is_none() {
            self.entries.push((type_id, Box::new(get_value())));
        }
    }
}
