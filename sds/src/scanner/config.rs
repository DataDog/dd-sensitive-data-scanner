#[cfg(feature = "wasm_incompatible")]
use crate::match_validation::config::{InternalMatchValidationType, MatchValidationType};
use crate::scanner::error::CreateScannerError;
use crate::scanner::CompiledRuleDyn;
use crate::Labels;

pub trait RuleConfig: Send + Sync {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError>;

    #[cfg(feature = "wasm_incompatible")]
    fn get_match_validation_type(&self) -> Option<&MatchValidationType>;

    #[cfg(feature = "wasm_incompatible")]
    fn get_internal_match_validation_type(&self) -> Option<InternalMatchValidationType> {
        self.get_match_validation_type()
            .map(|x| x.get_internal_match_validation_type())
    }
}
