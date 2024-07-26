use crate::scanner::cache_pool::CachePoolBuilder;
use crate::scanner::error::CreateScannerError;
use crate::scanner::CompiledRuleTrait;
use crate::Labels;

pub trait RuleConfig {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleTrait>, CreateScannerError>;
}
