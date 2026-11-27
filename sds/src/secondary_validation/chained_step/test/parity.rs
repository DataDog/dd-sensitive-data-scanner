//! Parity between the hand-written GitHub / Atlassian validators and the same schemes expressed
//! as chains. The chains never return `Error` on these inputs, so parity holds whatever the
//! `default_response`.

use super::{check, compiled, regex_step, step};
use crate::secondary_validation::chained_step::{ChainOutcome, CompiledChain};
use crate::secondary_validation::{AtlassianTokenChecksum, GithubTokenChecksum, Validator};
use serde_json::{Value as JsonValue, json};

fn github_chain() -> JsonValue {
    json!({"version": 1, "steps": [
        step("Split",
            json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": -1}),
            json!({"after": "last"})),
        // `+` keeps the body non-empty: the hand-written validator requires more than 6
        // characters.
        regex_step(
            json!({"param": "$last", "pattern": "(?<body>[A-Za-z0-9]+)(?<checksum>[A-Za-z0-9]{6})"}),
            json!({"body": "body", "checksum": "checksum"})),
        check("VerifyChecksum", json!({
            "payload": "$body", "embedded": "$checksum", "alg": "crc32", "scheme": "base62"})),
    ]})
}

fn atlassian_chain() -> JsonValue {
    json!({"version": 1, "steps": [
        // `+` keeps the prefix non-empty: the hand-written validator requires at least 9 bytes.
        regex_step(
            json!({"param": "$GLOBAL_MATCH", "pattern": "(?<prefix>[A-Za-z0-9_=-]+)(?<suffix>[0-9A-Fa-f]{8})"}),
            json!({"prefix": "prefix", "suffix": "suffix"})),
        check("VerifyChecksum", json!({
            "payload": "$prefix", "embedded": "$suffix", "alg": "crc32", "scheme": "hex"})),
    ]})
}

fn chain_accepts(chain: &CompiledChain, token: &str) -> bool {
    match chain.evaluate(token) {
        ChainOutcome::Valid => true,
        ChainOutcome::Invalid => false,
        ChainOutcome::Error => panic!("{token:?} could not be evaluated"),
    }
}

fn assert_parity(chain: &CompiledChain, validator: &dyn Validator, token: &str) {
    assert_eq!(
        chain_accepts(chain, token),
        validator.is_valid_match(token),
        "parity mismatch for {token:?}"
    );
}

/// SplitMix64: a tiny deterministic generator so the sweep is reproducible without a new
/// dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick(&mut self, alphabet: &[char]) -> char {
        alphabet
            .get(self.below(alphabet.len()))
            .copied()
            .unwrap_or('a')
    }

    fn string(&mut self, alphabet: &[char], len: usize) -> String {
        (0..len).map(|_| self.pick(alphabet)).collect()
    }
}

fn chars(ranges: &[(char, char)], extra: &str) -> Vec<char> {
    ranges
        .iter()
        .flat_map(|&(low, high)| low..=high)
        .chain(extra.chars())
        .collect()
}

fn alphanumeric() -> Vec<char> {
    chars(&[('0', '9'), ('A', 'Z'), ('a', 'z')], "")
}

/// Applies one random corruption, using `noise` for inserted / replaced characters.
fn corrupt(rng: &mut SplitMix64, token: &str, noise: &[char]) -> String {
    let mut chars: Vec<char> = token.chars().collect();
    if chars.is_empty() {
        return rng.string(noise, 3);
    }
    let position = rng.below(chars.len());
    match rng.below(6) {
        0 => {
            if let Some(slot) = chars.get_mut(position) {
                *slot = rng.pick(noise);
            }
        }
        1 => chars.truncate(position),
        2 => {
            chars.remove(position);
        }
        3 => chars.insert(position, rng.pick(noise)),
        4 => {
            if position + 1 < chars.len() {
                chars.swap(position, position + 1);
            }
        }
        _ => chars.retain(|&c| c != '_'),
    }
    chars.into_iter().collect()
}

fn github_token(rng: &mut SplitMix64) -> String {
    let prefixes = ["ghp", "gho", "ghs", "nawak_ghp", "b62", "x"];
    let prefix = prefixes
        .get(rng.below(prefixes.len()))
        .copied()
        .unwrap_or("ghp");
    let body_len = 1 + rng.below(40);
    let body = rng.string(&alphanumeric(), body_len);
    let checksum = base62::encode(crc32fast::hash(body.as_bytes()));
    format!("{prefix}_{body}{checksum:0>6}")
}

fn atlassian_token(rng: &mut SplitMix64) -> String {
    let body_alphabet = chars(&[('0', '9'), ('A', 'Z'), ('a', 'z')], "_=-");
    let body_len = rng.below(180);
    let prefix = format!("ATATT{}", rng.string(&body_alphabet, body_len));
    let crc = crc32fast::hash(prefix.as_bytes());
    let checksum = if rng.below(2) == 0 {
        format!("{crc:08X}")
    } else {
        format!("{crc:08x}")
    };
    format!("{prefix}{checksum}")
}

#[test]
fn github_chain_matches_existing_valid_vectors() {
    let chain = compiled(&github_chain());
    for token in [
        "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",
        "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",
        "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",
        "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",
        "nawak_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",
        "b62_QdwULL38u41vs1OcAjhKqcaSZ9W63r0Zu4ln",
    ] {
        assert!(chain_accepts(&chain, token), "{token}");
        assert_parity(&chain, &GithubTokenChecksum, token);
    }
}

#[test]
fn github_chain_matches_existing_invalid_vectors() {
    let chain = compiled(&github_chain());
    for token in [
        "ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V3",
        "ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V\u{f1}",
        "ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V/",
        "ghpM7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V4",
        "ghp_T4V4",
        // Edge cases around the 6-character checksum.
        "ghp_000000",
        "ghp_a000000",
        "ghp_",
        "_",
        "",
    ] {
        assert_parity(&chain, &GithubTokenChecksum, token);
    }
}

#[test]
fn atlassian_chain_matches_existing_valid_vectors() {
    let chain = compiled(&atlassian_chain());
    for token in [
        "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E2826606",
        "ATATT3xFfGF0Z0J8j7dew7xO2JMwbmnBZm-aJ5ORorE7qRgkDnmZYg9tpvatRzyvZNebxWeUxRZnSkEGeyAV3_Jew_YCxyCUsw_Ipefxsk0EFerD8PlRNEDtQQEmexYVpWbuTguSvV3USUg41GEdgTYa1MUK3YusfDWKzLthXBmkeUH4ZyaTp2Q=325540CC",
    ] {
        assert!(chain_accepts(&chain, token), "{token}");
        assert_parity(&chain, &AtlassianTokenChecksum, token);
    }
}

#[test]
fn atlassian_chain_matches_existing_invalid_vectors() {
    let chain = compiled(&atlassian_chain());
    for token in [
        "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E2826607",
        "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E282607",
        "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E282607G",
        "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQK~D9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E2826607",
        // Edge cases around the 8-character checksum: CRC32("") is 0, but the hand-written
        // validator requires a non-empty prefix.
        "00000000",
        "a00000000",
        "",
    ] {
        assert_parity(&chain, &AtlassianTokenChecksum, token);
    }
}

#[test]
fn github_chain_agrees_on_generated_tokens() {
    let chain = compiled(&github_chain());
    let mut rng = SplitMix64(0x5EED_0001);
    let noise = chars(&[('0', '9'), ('A', 'Z'), ('a', 'z')], "_-/~=\u{f1}\u{e9}");
    let (mut accepted, mut rejected) = (0, 0);
    for _ in 0..3000 {
        let token = github_token(&mut rng);
        assert!(chain_accepts(&chain, &token), "{token}");
        assert_parity(&chain, &GithubTokenChecksum, &token);
        let corrupted = corrupt(&mut rng, &token, &noise);
        assert_parity(&chain, &GithubTokenChecksum, &corrupted);
        if GithubTokenChecksum.is_valid_match(&corrupted) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    // The sweep must exercise both sides, otherwise it proves nothing.
    assert!(accepted > 0 && rejected > 1000, "{accepted} / {rejected}");
}

#[test]
fn atlassian_chain_agrees_on_generated_tokens() {
    let chain = compiled(&atlassian_chain());
    let mut rng = SplitMix64(0x5EED_0002);
    // ASCII only: the hand-written validator slices the `&str` at `len - 8`, which panics on a
    // non-ASCII character straddling that boundary.
    let noise = chars(&[(' ', '~')], "");
    let (mut accepted, mut rejected) = (0, 0);
    for _ in 0..3000 {
        let token = atlassian_token(&mut rng);
        assert!(chain_accepts(&chain, &token), "{token}");
        assert_parity(&chain, &AtlassianTokenChecksum, &token);
        let corrupted = corrupt(&mut rng, &token, &noise);
        assert_parity(&chain, &AtlassianTokenChecksum, &corrupted);
        if AtlassianTokenChecksum.is_valid_match(&corrupted) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(accepted > 0 && rejected > 1000, "{accepted} / {rejected}");
}
