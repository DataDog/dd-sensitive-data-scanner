use ahash::AHashSet;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{FakerValidationError, PseudonymizationType, build, validate};

#[derive(Debug, PartialEq, Eq, Error)]
pub enum StatelessPseudonymizerError {
    #[error("Pseudonymization terminal pool size must be non-zero")]
    EmptyTerminalPool,
    #[error(transparent)]
    InvalidPseudonymizationType(#[from] FakerValidationError),
}

#[derive(Debug, Clone)]
pub struct StatelessPseudonymizer {
    pseudonymization_type: PseudonymizationType,
    seed: String,
    version: String,
    rule_id: String,
    terminal_pool: Vec<String>,
    terminal_values: AHashSet<String>,
}

impl StatelessPseudonymizer {
    pub fn new(
        pseudonymization_type: PseudonymizationType,
        seed: impl Into<String>,
        version: impl Into<String>,
        rule_id: impl Into<String>,
        pool_size: usize,
    ) -> Result<Self, StatelessPseudonymizerError> {
        if pool_size == 0 {
            return Err(StatelessPseudonymizerError::EmptyTerminalPool);
        }

        validate(&pseudonymization_type)?;

        let seed = seed.into();
        let version = version.into();
        let rule_id = rule_id.into();
        let terminal_pool =
            terminal_pool(&pseudonymization_type, &seed, &version, &rule_id, pool_size)?;
        let terminal_values = terminal_pool.iter().cloned().collect();

        Ok(Self {
            pseudonymization_type,
            seed,
            version,
            rule_id,
            terminal_pool,
            terminal_values,
        })
    }

    pub fn terminal_pool(&self) -> &[String] {
        &self.terminal_pool
    }

    pub fn is_terminal(&self, value: &str) -> bool {
        self.terminal_values.contains(value)
    }

    pub fn replacement_for(&self, matched_value: &str) -> &str {
        let key = format!(
            "replacement:{}:{}:{}",
            self.version, self.rule_id, matched_value
        );
        let index = index_from_hmac(&self.seed, &key, self.terminal_pool.len());
        &self.terminal_pool[index]
    }

    pub fn pseudonymization_type(&self) -> &PseudonymizationType {
        &self.pseudonymization_type
    }
}

pub fn terminal_pool(
    pseudonymization_type: &PseudonymizationType,
    seed: &str,
    version: &str,
    rule_id: &str,
    pool_size: usize,
) -> Result<Vec<String>, StatelessPseudonymizerError> {
    if pool_size == 0 {
        return Err(StatelessPseudonymizerError::EmptyTerminalPool);
    }

    validate(pseudonymization_type)?;

    Ok((0..pool_size)
        .map(|pool_index| {
            let key = format!("terminal-pool:{version}:{rule_id}:{pool_index}");
            build(pseudonymization_type, &rng_seed_from_hmac(seed, &key))
        })
        .collect())
}

fn index_from_hmac(seed: &str, key: &str, pool_size: usize) -> usize {
    let digest = hmac_sha256(seed, key);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(bytes) % pool_size as u64) as usize
}

fn rng_seed_from_hmac(seed: &str, key: &str) -> String {
    let digest = hmac_sha256(seed, key);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hmac_sha256(seed: &str, key: &str) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;

    let mut key_bytes = seed.as_bytes().to_vec();
    if key_bytes.len() > BLOCK_SIZE {
        key_bytes = Sha256::digest(&key_bytes).to_vec();
    }
    key_bytes.resize(BLOCK_SIZE, 0);

    let mut outer_key_pad = [0x5c; BLOCK_SIZE];
    let mut inner_key_pad = [0x36; BLOCK_SIZE];
    for (index, byte) in key_bytes.iter().enumerate() {
        outer_key_pad[index] ^= byte;
        inner_key_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_key_pad);
    inner.update(key.as_bytes());
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_key_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use ahash::AHashMap;

    use super::*;

    fn faker_type() -> PseudonymizationType {
        let mut allowed_data = AHashMap::new();
        allowed_data.insert(
            "first_name".to_string(),
            vec!["Alice".to_string(), "Bob".to_string(), "Carol".to_string()],
        );
        allowed_data.insert(
            "last_name".to_string(),
            vec![
                "Smith".to_string(),
                "Jones".to_string(),
                "Miller".to_string(),
            ],
        );

        PseudonymizationType::Faker {
            string_builder: "{first_name} {last_name}".to_string(),
            allowed_data,
        }
    }

    #[test]
    fn terminal_pool_generation_is_deterministic() {
        let pseudonymization_type = faker_type();

        assert_eq!(
            terminal_pool(&pseudonymization_type, "shared-seed", "v1", "rule-id", 10).unwrap(),
            terminal_pool(&pseudonymization_type, "shared-seed", "v1", "rule-id", 10).unwrap()
        );
    }

    #[test]
    fn terminal_pool_changes_when_seed_changes() {
        let pseudonymization_type = faker_type();

        assert_ne!(
            terminal_pool(&pseudonymization_type, "shared-seed", "v1", "rule-id", 10).unwrap(),
            terminal_pool(&pseudonymization_type, "other-seed", "v1", "rule-id", 10).unwrap()
        );
    }

    #[test]
    fn terminal_pool_changes_when_version_changes() {
        let pseudonymization_type = faker_type();

        assert_ne!(
            terminal_pool(&pseudonymization_type, "shared-seed", "v1", "rule-id", 10).unwrap(),
            terminal_pool(&pseudonymization_type, "shared-seed", "v2", "rule-id", 10).unwrap()
        );
    }

    #[test]
    fn replacement_is_always_from_terminal_pool() {
        let pseudonymizer =
            StatelessPseudonymizer::new(faker_type(), "shared-seed", "v1", "rule-id", 10).unwrap();

        let replacement = pseudonymizer.replacement_for("John Doe");

        assert!(
            pseudonymizer
                .terminal_pool()
                .contains(&replacement.to_string())
        );
        assert!(pseudonymizer.is_terminal(replacement));
    }

    #[test]
    fn regex_terminal_pool_values_match_pattern() {
        let pseudonymization_type = PseudonymizationType::Regex {
            regex: r"[A-Z]{3}[0-9]{2}".to_string(),
        };
        let regex = ::regex::Regex::new(r"^[A-Z]{3}[0-9]{2}$").unwrap();

        let pool =
            terminal_pool(&pseudonymization_type, "shared-seed", "v1", "rule-id", 20).unwrap();

        assert!(pool.iter().all(|value| regex.is_match(value)));
    }

    #[test]
    fn rejects_empty_pool() {
        assert_eq!(
            StatelessPseudonymizer::new(faker_type(), "shared-seed", "v1", "rule-id", 0)
                .unwrap_err(),
            StatelessPseudonymizerError::EmptyTerminalPool
        );
    }

    #[test]
    fn terminal_pool_rejects_empty_pool() {
        assert_eq!(
            terminal_pool(&faker_type(), "shared-seed", "v1", "rule-id", 0).unwrap_err(),
            StatelessPseudonymizerError::EmptyTerminalPool
        );
    }

    #[test]
    fn hmac_sha256_matches_known_test_vector() {
        let digest = hmac_sha256("key", "The quick brown fox jumps over the lazy dog");
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert_eq!(
            actual,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
}
