#[cfg(feature = "match_validation")]
#[cfg(test)]
mod e2e_integration_test {
    use dd_sds::AwsConfig;
    use dd_sds::AwsType;
    use dd_sds::HttpValidatorHelper;
    use dd_sds::MatchAction;
    use dd_sds::MatchStatus;
    use dd_sds::MatchValidationType;
    use dd_sds::ProximityKeywordsConfig;
    use dd_sds::RegexRuleConfig;
    use dd_sds::ScannerBuilder;
    use serde::Deserialize;
    use serde::Serialize;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct E2ETestSecrets {
        pub datadog_api_key: String,
        pub github_api_key: String,
        pub aws_access_key_id: String,
        pub aws_secret_access_key: String,
    }

    fn load_env_secret(env_var: String) -> Result<E2ETestSecrets, std::env::VarError> {
        // env_var shall contain a json string with the secrets
        // let's retrieve its content form the env
        let env_var_content = std::env::var(&env_var)?;
        println!("Secrets loaded from env var {}: ", env_var_content);
        // let's deserialize the json content
        let secrets: E2ETestSecrets =
            serde_json::from_str(&env_var_content).expect("Failed to deserialize the secrets");
        Ok(secrets)
    }

    #[ignore]
    #[tokio::test]
    async fn test_datadog_match_validation_invalid_match() {
        use std::vec;

        let rule_dd = RegexRuleConfig::new("\\b[a-f0-9]{32}\\b")
            .match_action(MatchAction::Redact {
                replacement: "[DATADOG]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorHelper::new_datadog_config_builder().build(),
            ))
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["api_key".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_dd]).build().unwrap();

        let mut content =
            "content with a datadog api_key 0123456789abcdef0123456789abcdef".to_string();
        let mut all_rule_matches = vec![];
        let rule_matches = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_matches.len(), 1);
        assert_eq!(content, "content with a datadog api_key [DATADOG]");
        all_rule_matches.extend(rule_matches);

        assert!(scanner
            .validate_matches(&mut all_rule_matches)
            .await
            .is_ok());
        for rule_match in all_rule_matches {
            assert_eq!(rule_match.match_status, MatchStatus::Invalid);
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_datadog_match_validation_valid_and_invalid_match() {
        use std::vec;
        let secrets = load_env_secret("KEYS_FOR_END_2_END_TEST".to_string()).unwrap();
        let rule_dd = RegexRuleConfig::new("\\b[a-f0-9]{32}\\b")
            .match_action(MatchAction::Redact {
                replacement: "[DATADOG]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorHelper::new_datadog_config_builder().build(),
            ))
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["api_key".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_dd]).build().unwrap();

        let mut content = format!(
            "content with a datadog api_key {} and an other invalid api_key 0123456789abcdef0123456789abcdef", secrets.datadog_api_key);

        let mut all_rule_matches = vec![];
        let rule_matches = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_matches.len(), 2);
        assert_eq!(
            content,
            "content with a datadog api_key [DATADOG] and an other invalid api_key [DATADOG]"
        );
        all_rule_matches.extend(rule_matches);

        assert!(scanner
            .validate_matches(&mut all_rule_matches)
            .await
            .is_ok());
        assert_eq!(all_rule_matches[0].match_status, MatchStatus::Valid);
        assert_eq!(all_rule_matches[1].match_status, MatchStatus::Invalid);
    }

    #[ignore]
    #[tokio::test]
    async fn test_github_invalid_match() {
        let rule_ghp = RegexRuleConfig::new("\\bgh[opsu]_[0-9a-zA-Z]{36}\\b")
            .match_action(MatchAction::Redact {
                replacement: "[GITHUB]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorHelper::new_github_config_builder().build(),
            ))
            .build();

        let scanner = ScannerBuilder::new(&[rule_ghp]).build().unwrap();

        let mut content =
            "content with a github api key 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".to_string();
        let mut all_rule_matches = vec![];
        let rule_matches = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_matches.len(), 1);
        assert_eq!(content, "content with a github api key [GITHUB]");
        all_rule_matches.extend(rule_matches);

        assert!(scanner
            .validate_matches(&mut all_rule_matches)
            .await
            .is_ok());
        assert_eq!(all_rule_matches[0].match_status, MatchStatus::Invalid);
    }

    #[ignore]
    #[tokio::test]
    async fn test_github_valid_match() {
        let secrets = load_env_secret("KEYS_FOR_END_2_END_TEST".to_string()).unwrap();
        let rule_ghp = RegexRuleConfig::new("\\bgh[opsu]_[0-9a-zA-Z]{36}\\b")
            .match_action(MatchAction::Redact {
                replacement: "[GITHUB]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorHelper::new_github_config_builder().build(),
            ))
            .build();

        let scanner = ScannerBuilder::new(&[rule_ghp]).build().unwrap();

        let mut content = format!("content with a github api key {}", secrets.github_api_key);

        let mut all_rule_matches = vec![];
        let rule_matches = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_matches.len(), 1);
        assert_eq!(content, "content with a github api key [GITHUB]");
        all_rule_matches.extend(rule_matches);

        assert!(scanner
            .validate_matches(&mut all_rule_matches)
            .await
            .is_ok());
        assert_eq!(all_rule_matches[0].match_status, MatchStatus::Valid);
    }

    #[ignore]
    #[tokio::test]
    async fn test_mixed_http_validators() {
        let secrets = load_env_secret("KEYS_FOR_END_2_END_TEST".to_string()).unwrap();
        let rule_ghp = RegexRuleConfig::new("\\bgh[opsu]_[0-9a-zA-Z]{36}\\b")
            .match_action(MatchAction::Redact {
                replacement: "[GITHUB]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorHelper::new_github_config_builder().build(),
            ))
            .build();

        let rule_dd = RegexRuleConfig::new("\\b[a-f0-9]{32}\\b")
            .match_action(MatchAction::Redact {
                replacement: "[DATADOG]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorHelper::new_datadog_config_builder().build(),
            ))
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["api_key".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_dd, rule_ghp]).build().unwrap();

        let mut content = format!(
            "content with a datadog api_key {} and a github api key {}",
            secrets.datadog_api_key, secrets.github_api_key
        );
        let mut all_rule_matches = vec![];
        let rule_matches = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_matches.len(), 2);
        assert_eq!(
            content,
            "content with a datadog api_key [DATADOG] and a github api key [GITHUB]"
        );
        all_rule_matches.extend(rule_matches);

        assert!(scanner
            .validate_matches(&mut all_rule_matches)
            .await
            .is_ok());
        assert_eq!(all_rule_matches[0].match_status, MatchStatus::Valid);
        assert_eq!(all_rule_matches[1].match_status, MatchStatus::Valid);
    }

    #[ignore]
    #[tokio::test]
    async fn test_aws_simple_validation() {
        let secrets = load_env_secret("KEYS_FOR_END_2_END_TEST".to_string()).unwrap();
        let rule_aws_id = RegexRuleConfig::new("AKIA[0-9A-Z]{16}")
            .match_action(MatchAction::Redact {
                replacement: "[AWS_ID]".to_string(),
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsId))
            .build();

        let rule_aws_secret = RegexRuleConfig::new("[A-Za-z0-9/+]{40}")
            .match_action(MatchAction::Redact {
                replacement: "[AWS_SECRET]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["aws_secret".to_string()],
                excluded_keywords: vec![],
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsSecret(
                AwsConfig::default(),
            )))
            .build();

        let scanner = ScannerBuilder::new(&[rule_aws_id, rule_aws_secret])
            .build()
            .unwrap();

        let mut content = format!(
            "content with a valid aws_id {}, an invalid aws_id AKIAAAAAAAAAAAAAAAAA and an aws_secret {}",
            secrets.aws_access_key_id, secrets.aws_secret_access_key);
        let mut all_rule_matches = vec![];
        let rule_matches = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_matches.len(), 3);
        assert_eq!(
        content,
        "content with a valid aws_id [AWS_ID], an invalid aws_id [AWS_ID] and an aws_secret [AWS_SECRET]"
    );
        all_rule_matches.extend(rule_matches);

        assert!(scanner
            .validate_matches(&mut all_rule_matches)
            .await
            .is_ok());
        assert_eq!(all_rule_matches[0].match_status, MatchStatus::Valid);
        assert_eq!(all_rule_matches[1].match_status, MatchStatus::Invalid);
        assert_eq!(all_rule_matches[2].match_status, MatchStatus::Valid);
    }
}
