use crate::SecondaryValidator::{
    ChineseIdChecksum, GithubTokenChecksum, IbanChecker, JwtExpirationChecker, NhsCheckDigit,
};
use crate::{MatchAction, RegexRuleConfig, ScannerBuilder, SecondaryValidator};
use chrono::Utc;

#[test]
fn test_luhn_checksum() {
    let rule =
        RegexRuleConfig::new("(\\d{16})|((\\d{4} ){3}\\d{4})").match_action(MatchAction::Redact {
            replacement: "[credit card]".to_string(),
        });

    let rule_with_checksum = rule.validator(SecondaryValidator::LuhnChecksum).build();

    let scanner = ScannerBuilder::new(&[rule.build()]).build().unwrap();
    let mut content = "4556997807150071  4111 1111 1111 1111".to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 2);
    assert_eq!(content, "[credit card]  [credit card]");

    let scanner = ScannerBuilder::new(&[rule_with_checksum]).build().unwrap();
    let mut content = "4556997807150071  4111 1111 1111 1111".to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "4556997807150071  [credit card]");
}

#[test]
fn test_chinese_id_checksum() {
    let rule = RegexRuleConfig::new("\\d+").match_action(MatchAction::Redact {
        replacement: "[IDCARD]".to_string(),
    });

    let rule_with_checksum = rule.validator(ChineseIdChecksum).build();

    let scanner = ScannerBuilder::new(&[rule.build()]).build().unwrap();
    let mut content = "513231200012121657 513231200012121651".to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 2);
    assert_eq!(content, "[IDCARD] [IDCARD]");

    let scanner = ScannerBuilder::new(&[rule_with_checksum]).build().unwrap();
    let mut content = "513231200012121657 513231200012121651".to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[IDCARD] 513231200012121651");
}

#[test]
fn test_iban_checksum() {
    let rule_with_checksum = RegexRuleConfig::new("DE[0-9]+")
        .match_action(MatchAction::Redact {
            replacement: "[IBAN]".to_string(),
        })
        .validator(IbanChecker)
        .build();

    // Valid content with checksum
    let mut content = "number=DE44500105175407324931".to_string();
    let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
        .build()
        .unwrap();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "number=[IBAN]");

    // Invalid content with checksum
    let mut content = "number=DE34500105175407324931".to_string();
    let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
        .build()
        .unwrap();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 0);
    assert_eq!(content, "number=DE34500105175407324931");
}

#[test]
fn test_github_token_checksum() {
    let rule = RegexRuleConfig::new("[^ ]+").match_action(MatchAction::Redact {
        replacement: "[GITHUB]".to_string(),
    });

    let rule_with_checksum = rule.validator(GithubTokenChecksum).build();

    let scanner = ScannerBuilder::new(&[rule.build()]).build().unwrap();
    let mut content =
        "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
            .to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 2);
    assert_eq!(content, "[GITHUB] [GITHUB]");

    let scanner = ScannerBuilder::new(&[rule_with_checksum]).build().unwrap();
    let mut content =
        "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
            .to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[GITHUB] ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5");
}

#[test]
fn test_jwt_expiration_checker() {
    use crate::secondary_validation::generate_jwt;
    let rule = RegexRuleConfig::new("[A-Za-z0-9._-]+")
        .match_action(MatchAction::Redact {
            replacement: "[JWT]".to_string(),
        })
        .validator(JwtExpirationChecker)
        .build();
    let scanner = ScannerBuilder::new(&[rule]).build().unwrap();
    let future_time_as_string = (Utc::now().timestamp() + 1000000).to_string();

    let mut content = generate_jwt(future_time_as_string).to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[JWT]");

    let past_time_as_string = (Utc::now().timestamp() - 1000000).to_string();
    let mut content = generate_jwt(past_time_as_string).to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_nhs_checksum() {
    let rule_with_checksum = RegexRuleConfig::new(".+")
        .match_action(MatchAction::Redact {
            replacement: "[NHS]".to_string(),
        })
        .validator(NhsCheckDigit)
        .build();

    let mut content = "1234567881".to_string();
    // Test matching NHS number with checksum
    let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
        .build()
        .unwrap();
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[NHS]");
}
