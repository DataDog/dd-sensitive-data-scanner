use crate::scanner::RootRuleConfig;
use crate::SecondaryValidator::{
    ChineseIdChecksum, GithubTokenChecksum, IbanChecker, JwtExpirationChecker, NhsCheckDigit,
};
use crate::{MatchAction, RegexRuleConfig, ScannerBuilder, SecondaryValidator};
use chrono::Utc;

#[test]
fn test_luhn_checksum() {
    let match_action = MatchAction::Redact {
        replacement: "[credit card]".to_string(),
    };

    let rule = RegexRuleConfig::new("(\\d{16})|((\\d{4} ){3}\\d{4})");

    let rule_with_checksum = RootRuleConfig::new(
        rule.with_validator(Some(SecondaryValidator::LuhnChecksum))
            .build(),
    )
    .match_action(match_action.clone());

    let scanner =
        ScannerBuilder::new(&[RootRuleConfig::new(rule.build()).match_action(match_action)])
            .build()
            .unwrap();
    let mut content = "4556997807150071  4111 1111 1111 1111".to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(content, "[credit card]  [credit card]");

    let scanner = ScannerBuilder::new(&[rule_with_checksum]).build().unwrap();
    let mut content = "4556997807150071  4111 1111 1111 1111".to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "4556997807150071  [credit card]");
}

#[test]
fn test_chinese_id_checksum() {
    let match_action = MatchAction::Redact {
        replacement: "[IDCARD]".to_string(),
    };

    let rule = RegexRuleConfig::new("\\d+"); //.match_action(match_action);

    let rule_with_checksum =
        RootRuleConfig::new(rule.with_validator(Some(ChineseIdChecksum)).build())
            .match_action(match_action.clone());

    let scanner =
        ScannerBuilder::new(&[RootRuleConfig::new(rule.build()).match_action(match_action)])
            .build()
            .unwrap();
    let mut content = "513231200012121657 513231200012121651".to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(content, "[IDCARD] [IDCARD]");

    let scanner = ScannerBuilder::new(&[rule_with_checksum]).build().unwrap();
    let mut content = "513231200012121657 513231200012121651".to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[IDCARD] 513231200012121651");
}

#[test]
fn test_iban_checksum() {
    let rule_with_checksum = RootRuleConfig::new(
        RegexRuleConfig::new("DE[0-9]+")
            .with_validator(Some(IbanChecker))
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[IBAN]".to_string(),
    });

    // Valid content with checksum
    let mut content = "number=DE44500105175407324931".to_string();
    let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
        .build()
        .unwrap();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "number=[IBAN]");

    // Invalid content with checksum
    let mut content = "number=DE34500105175407324931".to_string();
    let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
        .build()
        .unwrap();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 0);
    assert_eq!(content, "number=DE34500105175407324931");
}

#[test]
fn test_github_token_checksum() {
    let rule = RegexRuleConfig::new("[^ ]+");
    let match_action = MatchAction::Redact {
        replacement: "[GITHUB]".to_string(),
    };

    let rule_with_checksum =
        RootRuleConfig::new(rule.with_validator(Some(GithubTokenChecksum)).build())
            .match_action(match_action.clone());

    let scanner =
        ScannerBuilder::new(&[RootRuleConfig::new(rule.build()).match_action(match_action)])
            .build()
            .unwrap();

    let mut content =
        "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
            .to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(content, "[GITHUB] [GITHUB]");

    let scanner = ScannerBuilder::new(&[rule_with_checksum]).build().unwrap();
    let mut content =
        "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
            .to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[GITHUB] ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5");
}

#[test]
fn test_jwt_expiration_checker() {
    use crate::secondary_validation::generate_jwt;
    let rule = RootRuleConfig::new(
        RegexRuleConfig::new("[A-Za-z0-9._-]+")
            .with_validator(Some(JwtExpirationChecker))
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[JWT]".to_string(),
    });
    let scanner = ScannerBuilder::new(&[rule]).build().unwrap();
    let future_time_as_string = (Utc::now().timestamp() + 1000000).to_string();

    let mut content = generate_jwt(future_time_as_string).to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[JWT]");

    let past_time_as_string = (Utc::now().timestamp() - 1000000).to_string();
    let mut content = generate_jwt(past_time_as_string).to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_nhs_checksum() {
    let rule_with_checksum = RootRuleConfig::new(
        RegexRuleConfig::new(".+")
            .with_validator(Some(NhsCheckDigit))
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[NHS]".to_string(),
    });

    let mut content = "1234567881".to_string();
    // Test matching NHS number with checksum
    let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
        .build()
        .unwrap();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "[NHS]");
}
