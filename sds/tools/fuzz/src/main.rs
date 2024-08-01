// This needs cleaned up a bit before clippy should run here
#![allow(warnings)]

use afl::fuzz;
use dd_sds::{MatchAction, PartialRedactDirection, RegexRuleConfig, ScannerBuilder, Scope};
use rand::{rngs::StdRng, Rng, SeedableRng};

#[cfg(not(feature = "manual_test"))]
fn main() {
    fuzz!(|data: &[u8]| {
        run_raw_fuzz(data);
    });
}

#[cfg(feature = "manual_test")]
fn main() {
    use std::io::{stdin, Read};

    let mut input = vec![];
    stdin().read_to_end(&mut input).unwrap();
    run_raw_fuzz(&input);
}

fn split_bytes_once(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(i) = input.iter().position(|b| *b == b',') {
        Some((&input[0..i], &input[i + 1..]))
    } else {
        None
    }
}

fn run_raw_fuzz(bytes: &[u8]) -> Option<()> {
    let (pattern, bytes) = split_bytes_once(bytes)?;
    let (input, rand_seed) = split_bytes_once(bytes)?;

    let pattern_str = std::str::from_utf8(pattern).ok()?;
    let input_str = std::str::from_utf8(input).ok()?;

    let mut rng_seed: u64 = 0;
    for i in 0..8 {
        if rand_seed.len() > i {
            rng_seed <<= 8;
            rng_seed += rand_seed[i] as u64;
        }
    }

    let rng = StdRng::seed_from_u64(rng_seed);
    run_fuzz(pattern_str, input_str, rng);

    Some(())
}

fn gen_direction(rng: &mut StdRng) -> PartialRedactDirection {
    if rng.gen_bool(0.5) {
        PartialRedactDirection::FirstCharacters
    } else {
        PartialRedactDirection::LastCharacters
    }
}

fn gen_match_action(rng: &mut StdRng) -> MatchAction {
    match rng.gen_range::<u8, _>(0..4) {
        0 => MatchAction::None,
        1 => MatchAction::Hash,
        2 => MatchAction::Redact {
            // TODO: generate random replacement string
            replacement: "[REDACT]".to_string(),
        },
        _ => MatchAction::PartialRedact {
            direction: gen_direction(rng),
            // TODO: The core lib can panic if this is 0, need to fix that
            character_count: rng.gen_range(1..20),
        },
    }
}

fn run_fuzz(pattern: &str, input: &str, mut rng: StdRng) {
    let match_action = gen_match_action(&mut rng);

    #[cfg(feature = "manual_test")]
    {
        println!("Pattern: {:?}", pattern);
        println!("Input: {:?}", input);
        println!("Input len: {:?}", input.len());
        println!("Match action: {:?}", match_action);
    }

    let scanner_result = ScannerBuilder::new(&[RegexRuleConfig::new(pattern)
        .match_action(match_action)
        .build()])
    .with_keywords_should_match_event_paths(true)
    .build();

    if let Ok(scanner) = scanner_result {
        let mut mutated_input = input.to_string();
        let sds_matches = scanner.scan(&mut mutated_input);
        #[cfg(feature = "manual_test")]
        {
            println!("SDS matches: {:?}", sds_matches);
            println!("Mutated input: {:?}", mutated_input);
        }
        // compare matches with hyperscan
        #[cfg(feature = "hyperscan")]
        {
            // TODO: an unwrap here could find patterns SDS allows that hyperscan doesn't
            if let Ok(hyperscan) = hyperscan::compile_hyperscan(pattern) {
                let hyperscan_matches = hyperscan::get_hyperscan_matches(&hyperscan, input);

                // There are known differences between SDS and Hyperscan for laziness which can
                // change the exact matches and even count of matches. It should not change IF
                // a match is found or not though.
                assert_eq!(!sds_matches.is_empty(), !hyperscan_matches.is_empty());
            }
        }
    }
}

#[cfg(feature = "hyperscan")]
mod hyperscan {
    use hyperscan::{compile, BlockDatabase, Matching, Pattern, Patterns};

    pub fn compile_hyperscan(pattern: &str) -> Result<BlockDatabase, ()> {
        compile(Patterns(vec![Pattern::new(pattern)
            .unwrap()
            .dot_all()
            .allow_empty()
            .left_most()
            .utf8()]))
        .map_err(|_| ())
    }

    pub fn get_hyperscan_matches(regex: &BlockDatabase, input: &str) -> Vec<(usize, usize)> {
        let scratch_space = regex.alloc_scratch().unwrap();
        let mut hyperscan_matches = vec![];
        let _ = regex.scan(&input, &scratch_space, |_, start, end, _| {
            hyperscan_matches.push((start as usize, end as usize));
            Matching::Continue
        });
        hyperscan_matches
    }
}
