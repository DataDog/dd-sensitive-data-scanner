#[cfg(feature = "match_validation")]
use crate::match_validation::config::{InternalMatchValidationType, MatchValidationType};
use crate::scanner::cache_pool::CachePoolBuilder;
use crate::scanner::error::CreateScannerError;
use crate::scanner::CompiledRuleDyn;
use crate::Labels;

pub trait RuleConfig: Send + Sync {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError>;
    #[cfg(feature = "match_validation")]
    fn get_match_validation_type(&self) -> Option<&MatchValidationType>;
    #[cfg(feature = "match_validation")]
    fn get_internal_match_validation_type(&self) -> Option<InternalMatchValidationType> {
        self.get_match_validation_type()
            .map(|x| x.get_internal_match_validation_type())
    }
}
