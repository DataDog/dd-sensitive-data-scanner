use crate::scanner::cache_pool::CachePoolBuilder;
use crate::scanner::error::CreateScannerError;
use crate::scanner::CompiledRuleDyn;
use crate::Labels;
use std::any::Any;
use std::hash::{Hash, Hasher};

/// This should be implemented for any new Rule config type.
/// Configs that are considered equal (according to `PartialEq`) may be re-used
pub trait RuleConfig: Send + Sync + Sized + PartialEq + Eq + Hash + 'static {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError>;
}

/// This is an internal rule config trait, and is automatically implemented where needed.
/// `RuleConfig` can be used anywhere `RuleConfigDyn` is required
pub trait RuleConfigDyn: Send + Sync {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError>;

    fn is_equal_to(&self, config: &dyn RuleConfigDyn) -> bool;

    fn as_any(&self) -> &dyn Any;

    fn dyn_hash(&self, hasher: &mut dyn Hasher);
}

impl<T: RuleConfig> RuleConfigDyn for T {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError> {
        T::convert_to_compiled_rule(self, rule_index, label, cache_pool_builder)
    }

    fn is_equal_to(&self, config: &dyn RuleConfigDyn) -> bool {
        if let Some(x) = config.as_any().downcast_ref::<T>() {
            // Now that we have two concrete `T` types, `PartialEq` can be used
            self == x
        } else {
            // Not the same type of config
            false
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn dyn_hash(&self, mut hasher: &mut dyn Hasher) {
        T::hash(self, &mut hasher)
    }
}
