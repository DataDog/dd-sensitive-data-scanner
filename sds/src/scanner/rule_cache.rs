use crate::scanner::config::RuleConfigDyn;
use crate::CompiledRuleDyn;
use ahash::AHashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::Weak;

pub struct RuleCache {
    map: AHashMap<RuleCacheKey, Weak<dyn CompiledRuleDyn>>,
}

impl RuleCache {
    pub fn new() -> Self {
        Self {
            map: AHashMap::new(),
        }
    }

    /// Cleans up any configuration no longer used in Scanners. Should be called periodically.
    pub fn gc(&mut self) {
        self.map.retain(|k, v| v.strong_count() > 0);
    }

    /// Check if a rule for this config already exists, and returns a copy if it does
    pub fn get(&self, config: &Arc<dyn RuleConfigDyn>) -> Option<Arc<dyn CompiledRuleDyn>> {
        match self.map.get(&RuleCacheKey(config.clone())) {
            None => None,
            Some(weak) => weak.upgrade(),
        }
    }

    /// Inserts a new rule into the cache. The "memoized" rule is returned and should be
    /// used instead of the one passed in. This ensures that if there were duplicates of
    /// a rule being created at the same time, only one is kept.
    pub fn insert(
        &mut self,
        config: &Arc<dyn RuleConfigDyn>,
        rule: Arc<dyn CompiledRuleDyn>,
    ) -> Arc<dyn CompiledRuleDyn> {
        if let Some(cached) = self.get(config) {
            cached
        } else {
            self.map
                .insert(RuleCacheKey(config.clone()), Arc::downgrade(&rule));
            rule
        }
    }
}

// Provides Eq / Hash
struct RuleCacheKey(Arc<dyn RuleConfigDyn>);

impl PartialEq for RuleCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.is_equal_to(other.0.as_ref())
    }
}

impl Eq for RuleCacheKey {}

impl Hash for RuleCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.dyn_hash(state)
    }
}
