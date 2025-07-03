use std::fs::File;
use std::io::BufRead;

use crate::parser::regex_parser::parse_regex_pattern;

#[test]
fn simple_patterns_can_be_parsed() {
    check_patterns_can_be_parsed(&read_file_lines("data/simple_patterns.txt"));
}

fn check_patterns_can_be_parsed(patterns: &[String]) {
    for (i, pattern) in patterns.iter().enumerate() {
        if let Err(err) = parse_regex_pattern(pattern) {
            println!("Input {}: {}", i + 1, pattern);
            panic!("Failed to parse input: {err:?}");
        }
    }
}

pub(crate) fn read_file_lines(filename: &str) -> Vec<String> {
    let file = File::open(filename).unwrap();
    std::io::BufReader::new(file)
        .lines()
        .map(|result| result.unwrap())
        .collect()
}
