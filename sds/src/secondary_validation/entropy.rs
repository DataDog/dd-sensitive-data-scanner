use crate::secondary_validation::Validator;

// 1.0 means 100% uniformly random. 0.90 is meant as a somewhat strict starting point
const NORMALIZED_ENTROPY_THRESHOLD: f32 = 0.90;

pub struct EntropyCheck;

impl Validator for EntropyCheck {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        normalized_entropy(regex_match) >= NORMALIZED_ENTROPY_THRESHOLD
    }
}

fn normalized_entropy(input: &str) -> f32 {
    let custom_entropy = raw_shannon_entropy_alphanumeric(input);
    let charset_size = detect_charset_size(input);
    let max_entropy = (charset_size as f32).log2();

    (custom_entropy / max_entropy).min(1.0)
}

// tries to determine the number of chars in the charset used for the input string (e.g. hex vs base64)
fn detect_charset_size(input: &str) -> usize {
    let mut has_digits = false;
    let mut has_lower_hex = false;
    let mut has_lowercase = false;
    let mut has_upper_hex = false;
    let mut has_uppercase = false;

    for ch in input.chars() {
        match ch {
            '0'..='9' => has_digits = true,
            'a'..='f' => has_lower_hex = true,
            'g'..='z' => has_lowercase = true,
            'A'..='F' => has_upper_hex = true,
            'G'..='Z' => has_uppercase = true,
            _ => {}
        }
    }

    let mut size = 0;

    if has_digits {
        size += 10;
    }

    if has_lowercase {
        size += 26;
    } else if has_lower_hex {
        size += 6;
    }

    if has_uppercase {
        size += 26;
    } else if has_upper_hex {
        size += 6;
    }

    size
}

// calculates shannon entropy only for ascii alphanumeric chars
fn raw_shannon_entropy_alphanumeric(input: &str) -> f32 {
    let mut entropy = 0.0;
    let mut counts = [0usize; ('z' as usize + 1)];
    let mut num_bytes = 0;

    for c in input.chars().filter(|c| c.is_ascii_alphanumeric()) {
        num_bytes += 1;
        counts[c as usize] += 1;
    }

    #[allow(clippy::needless_range_loop)]
    for i in ('0' as usize)..('z' as usize) {
        let count = counts[i];
        if count == 0 {
            continue;
        }
        let p: f32 = (count as f32) / (num_bytes as f32);
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::Validator;
    use crate::secondary_validation::entropy::EntropyCheck;

    #[test]
    fn validate_entropy_validator() {
        let valid_inputs = vec![
            "48b0ee9e-953f-dede-2695-ca96cd3c750e",
            "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",
            "ATATT3xFfGF0GfzfABO7-w-AdvXhHYHF4FnAa1jDw5jlp5U6e5flMKFVQ6eXpOhYyuaXg5pe7ZsHIknCKs3CeS_tTjuLVtQhcfap3JQ0q9oRM1_FqnNZQpYjF7MKtxrIDxGHgrWh2kyAsXcLHCbuydTdAbSvZXVfNX25wb0EozWMKJFWfQL6Wtk=AB5D27B0",
        ];

        for input in valid_inputs {
            println!("Valid input: {input}");
            assert!(EntropyCheck.is_valid_match(input));
        }

        let invalid_inputs = vec![
            "NobodyexpectstheSpanishInquisition",
            "Itsjustafleshwound",
            "Yourmotherwasahamsterandyourfatherelsmeltelderberries",
            "YOUR_API_KEY_GOES_HERE",
        ];

        for input in invalid_inputs {
            println!("Invalid input: {input}");
            assert!(!EntropyCheck.is_valid_match(input));
        }
    }
}
