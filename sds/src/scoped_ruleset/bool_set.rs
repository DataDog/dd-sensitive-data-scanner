/// This allows keeping track of multiple (contiguous) boolean flags,
/// and efficiently resetting all of them.

pub struct BoolSet {
    rule_used: Vec<bool>,
}

impl BoolSet {
    pub fn new(num_rules: usize) -> Self {
        Self {
            rule_used: vec![false; num_rules],
        }
    }

    pub fn get(&self, index: usize) -> bool {
        self.rule_used[index]
    }
    pub fn get_and_set(&mut self, index: usize) -> bool {
        let result = self.rule_used[index];
        self.rule_used[index] = true;
        result
    }

    pub fn reset(&mut self) {
        // Note: An implementation with "generations" was tried to prevent
        // having to reset all flags, but surprisingly it was slightly slower in benchmarks.
        self.rule_used.fill(false);
    }
}
