use crate::scanner::error::CreateScannerError;
use crate::scanner::CompiledRuleDyn;
use crate::Labels;

pub trait RuleConfig: Send + Sync {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError>;
}
