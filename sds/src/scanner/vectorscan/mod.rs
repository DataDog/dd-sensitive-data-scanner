use ahash::AHashSet;
use vectorscan_rs::{BlockDatabase, BlockScanner, Flag, Pattern, Scan};

#[cfg(test)]
mod tests;

/// Wraps a compiled vectorscan multi-pattern database for use as a pre-filter
/// in the SDS scanning loop. Patterns that fail vectorscan compilation are tracked
/// as fallback rules and always bypass the pre-filter.
pub struct VectorscanDb {
    db: BlockDatabase,
    /// Maps vectorscan pattern ID (u32) -> SDS rule index (usize)
    pattern_id_to_rule_index: Vec<usize>,
    /// Rule indices whose patterns could not be compiled for vectorscan.
    /// These always bypass the pre-filter.
    fallback_rules: AHashSet<usize>,
}

#[derive(Debug)]
pub enum VectorscanBuildError {
    /// No patterns could be compiled for vectorscan
    NoValidPatterns,
    /// Vectorscan database compilation failed
    CompilationFailed,
}

impl VectorscanDb {
    /// Build a vectorscan database from SDS regex patterns.
    ///
    /// `patterns` is a list of `(rule_index, sds_pattern_string)` pairs.
    /// Patterns are converted to vectorscan-compatible form (capture groups stripped).
    /// Patterns that fail compilation are tracked as fallback rules.
    pub fn new(patterns: &[(usize, &str)]) -> Result<Self, VectorscanBuildError> {
        let mut vs_patterns = Vec::new();
        let mut pattern_id_to_rule_index = Vec::new();
        let mut fallback_rules = AHashSet::new();

        let flags = Flag::UTF8 | Flag::SOM_LEFTMOST;

        for (rule_index, sds_pattern) in patterns {
            match convert_pattern_for_vectorscan(sds_pattern) {
                Ok(vs_pattern_str) => {
                    // Try compiling this single pattern to verify vectorscan compatibility.
                    // Also reject patterns with non-ASCII literals in character classes,
                    // since vectorscan may handle these differently than regex-automata.
                    if has_non_ascii_in_pattern(&vs_pattern_str) {
                        fallback_rules.insert(*rule_index);
                        continue;
                    }

                    let test_pattern =
                        Pattern::new(vs_pattern_str.clone().into_bytes(), flags, Some(0));
                    if BlockDatabase::new(vec![test_pattern]).is_ok() {
                        let pattern_id = vs_patterns.len() as u32;
                        vs_patterns.push(Pattern::new(
                            vs_pattern_str.into_bytes(),
                            flags,
                            Some(pattern_id),
                        ));
                        pattern_id_to_rule_index.push(*rule_index);
                    } else {
                        fallback_rules.insert(*rule_index);
                    }
                }
                Err(_) => {
                    fallback_rules.insert(*rule_index);
                }
            }
        }

        if vs_patterns.is_empty() {
            return Err(VectorscanBuildError::NoValidPatterns);
        }

        let db = BlockDatabase::new(vs_patterns)
            .map_err(|_| VectorscanBuildError::CompilationFailed)?;

        Ok(Self {
            db,
            pattern_id_to_rule_index,
            fallback_rules,
        })
    }

    /// Scan content and return the set of rule indices that had at least one match.
    pub fn get_matching_rules(&self, content: &str) -> AHashSet<usize> {
        let mut matching_rules = AHashSet::new();
        let data = content.as_bytes();

        // We need a scanner with scratch space. BlockScanner borrows the DB,
        // so we can't easily use thread_local with lifetime-bound scanners.
        // Instead, create a fresh scanner per call (scratch allocation is fast
        // after the first time due to vectorscan's internal caching).
        let mut scanner = match BlockScanner::new(&self.db) {
            Ok(s) => s,
            Err(_) => return matching_rules,
        };

        let pattern_id_to_rule = &self.pattern_id_to_rule_index;
        let _ = scanner.scan(data, |id, _from, _to, _flags| {
            if let Some(&rule_index) = pattern_id_to_rule.get(id as usize) {
                matching_rules.insert(rule_index);
            }
            Scan::Continue
        });

        matching_rules
    }

    /// Returns true if the given rule index is a fallback rule (pattern could not
    /// be compiled for vectorscan, so it must always be scanned with regex-automata).
    pub fn is_fallback_rule(&self, rule_index: usize) -> bool {
        self.fallback_rules.contains(&rule_index)
    }

    /// Returns true if the given rule index was successfully indexed by vectorscan
    /// (i.e., it was compiled into the multi-pattern database).
    pub fn has_rule(&self, rule_index: usize) -> bool {
        self.pattern_id_to_rule_index.contains(&rule_index)
    }

    /// Number of patterns successfully compiled for vectorscan.
    #[cfg(test)]
    pub fn compiled_pattern_count(&self) -> usize {
        self.pattern_id_to_rule_index.len()
    }

    /// Number of patterns that fell back to regex-automata only.
    #[cfg(test)]
    pub fn fallback_pattern_count(&self) -> usize {
        self.fallback_rules.len()
    }
}

/// Convert an SDS pattern string to a vectorscan-compatible pattern.
///
/// This converts the SDS regex syntax to Rust regex syntax (which is close to
/// what vectorscan accepts), then applies transformations to make it vectorscan-compatible:
/// - Strips named capture groups (vectorscan doesn't support them)
/// - Strips inline flag groups like (?-u:...) (vectorscan doesn't support them)
fn convert_pattern_for_vectorscan(sds_pattern: &str) -> Result<String, String> {
    use crate::normalization::rust_regex_adapter::convert_to_rust_regex;

    let rust_pattern =
        convert_to_rust_regex(sds_pattern).map_err(|e| format!("Parse error: {e:?}"))?;

    let mut stripped = strip_named_capture_groups(&rust_pattern);
    stripped = strip_inline_flag_groups(&stripped);

    Ok(stripped)
}

/// Check if a pattern contains non-ASCII literal characters.
/// Vectorscan may handle multi-byte UTF-8 characters differently in character classes.
fn has_non_ascii_in_pattern(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        if chars[i] == '\\' && i + 1 < len {
            // Skip escape sequences (e.g., \x{...}, \p{...})
            i += 2;
            continue;
        }
        if !chars[i].is_ascii() {
            return true;
        }
        i += 1;
    }
    false
}

/// Strip inline flag groups from a regex pattern string.
/// Converts `(?flags:...)` to `(...)`, e.g. `(?-u:\b)` becomes `(\b)`.
/// Vectorscan doesn't support Rust regex inline flag groups.
fn strip_inline_flag_groups(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '\\' && i + 1 < len {
            result.push(chars[i]);
            result.push(chars[i + 1]);
            i += 2;
            continue;
        }

        // Check for (?flags:...) — flags are letters and '-', followed by ':'
        if chars[i] == '(' && i + 1 < len && chars[i + 1] == '?' {
            let mut j = i + 2;
            // Scan flags portion (letters and '-')
            while j < len && (chars[j].is_ascii_alphabetic() || chars[j] == '-') {
                j += 1;
            }
            // If we hit a ':' and consumed at least one flag char, it's an inline flag group
            if j < len && chars[j] == ':' && j > i + 2 {
                // Replace (?flags: with just (
                result.push('(');
                i = j + 1;
                continue;
            }
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Strip named capture groups from a regex pattern string.
/// Converts `(?<name>...)` and `(?P<name>...)` to `(...)`.
fn strip_named_capture_groups(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '\\' && i + 1 < len {
            // Escaped character — pass through as-is
            result.push(chars[i]);
            result.push(chars[i + 1]);
            i += 2;
            continue;
        }

        // Check for (?< or (?P<
        if chars[i] == '('
            && i + 1 < len
            && chars[i + 1] == '?'
        {
            if i + 2 < len && chars[i + 2] == '<' && i + 3 < len && chars[i + 3] != '=' && chars[i + 3] != '!' {
                // (?<name>...) - strip the ?<name> part
                // Find the closing >
                let mut j = i + 3;
                while j < len && chars[j] != '>' {
                    j += 1;
                }
                if j < len {
                    // Replace with just (
                    result.push('(');
                    i = j + 1;
                    continue;
                }
            } else if i + 2 < len && chars[i + 2] == 'P' && i + 3 < len && chars[i + 3] == '<' {
                // (?P<name>...) - strip the ?P<name> part
                let mut j = i + 4;
                while j < len && chars[j] != '>' {
                    j += 1;
                }
                if j < len {
                    result.push('(');
                    i = j + 1;
                    continue;
                }
            }
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}
