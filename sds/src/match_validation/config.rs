use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    hash::{Hash, Hasher},
    ops::Range,
    time::Duration,
    vec,
};
pub const DEFAULT_HTTPS_TIMEOUT_SEC: u64 = 3;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AwsConfig {
    // Override default AWS STS endpoint for testing
    pub aws_sts_endpoint: String,
    // Override default datetime for testing
    pub forced_datetime_utc: Option<DateTime<Utc>>,
    pub timeout: Duration,
}

impl Default for AwsConfig {
    fn default() -> Self {
        AwsConfig {
            aws_sts_endpoint: "https://sts.amazonaws.com".to_string(),
            forced_datetime_utc: None,
            timeout: Duration::from_secs(DEFAULT_HTTPS_TIMEOUT_SEC),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AwsType {
    AwsId,
    AwsSecret(AwsConfig),
    AwsSession,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RequestHeader {
    pub key: String,
    // $MATCH is a special keyword that will be replaced by the matched string
    pub value: String,
}

impl RequestHeader {
    pub fn get_value_with_match(&self, matche: &str) -> String {
        // Replace $MATCH in value
        let mut value = self.value.clone();
        value = value.replace("$MATCH", matche);
        value
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]

pub struct HttpValidatorOption {
    pub timeout: Duration,
    // TODO(trosenblatt) add more options
    // pub max_retries: u64,
    // pub retry_delay: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HttpValidatorConfig {
    pub endpoint: String,
    pub method: HttpMethod,
    pub request_header: Vec<RequestHeader>,
    pub valid_http_status_code: Vec<Range<u16>>,
    pub invalid_http_status_code: Vec<Range<u16>>,
    pub options: HttpValidatorOption,
}

impl HttpValidatorConfig {
    pub fn new(endpoint: &str) -> Self {
        HttpValidatorConfig {
            endpoint: endpoint.to_string(),
            method: HttpMethod::Get,
            request_header: vec![],
            valid_http_status_code: vec![200..300],
            invalid_http_status_code: vec![400..500],
            options: HttpValidatorOption {
                timeout: Duration::from_secs(DEFAULT_HTTPS_TIMEOUT_SEC),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum MatchValidationType {
    Aws(AwsType),
    CustomHttp(HttpValidatorConfig),
}

impl MatchValidationType {
    // Method used to check if the validator can be created based on this type
    pub fn can_create_match_validator(&self) -> bool {
        match self {
            MatchValidationType::Aws(aws_type) => match aws_type {
                AwsType::AwsSecret(_) => true,
                _ => false,
            },
            MatchValidationType::CustomHttp(_) => true,
        }
    }
}

// Implement PartialEq and Eq to compare the variant type
impl PartialEq for MatchValidationType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MatchValidationType::Aws(_), MatchValidationType::Aws(_)) => true,
            (MatchValidationType::CustomHttp(a), MatchValidationType::CustomHttp(b)) => {
                a.endpoint == b.endpoint
            }
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

impl Eq for MatchValidationType {}

// Implement Hash to hash only the variant type
// For Split Keys (like aws) we want the same validator for all aws types
impl Hash for MatchValidationType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            MatchValidationType::Aws(_) => {
                std::mem::discriminant(self).hash(state);
            }
            MatchValidationType::CustomHttp(a) => {
                a.endpoint.hash(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_match_validation_type_hash() {
        let aws_validator1 = MatchValidationType::Aws(AwsType::AwsId);
        let aws_validator2 = MatchValidationType::Aws(AwsType::AwsSecret(AwsConfig::default()));
        let custom_http_validator1 =
            MatchValidationType::CustomHttp(HttpValidatorConfig::new("https://example.com"));
        let custom_http_validator2 =
            MatchValidationType::CustomHttp(HttpValidatorConfig::new("https://example2.com"));

        let mut map: HashMap<MatchValidationType, String> = HashMap::new();

        map.insert(aws_validator1, "Secret".to_string());
        assert_eq!(
            map.get(&aws_validator2),
            Some("Secret".to_string()).as_ref()
        );
        map.insert(custom_http_validator1, "value".to_string());
        assert_eq!(map.len(), 2);

        map.insert(custom_http_validator2, "value".to_string());
        assert_eq!(map.len(), 3);
    }
}
