use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{hash::Hash, ops::Range, time::Duration, vec};
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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
    pub fn get_internal_match_validation_type(&self) -> InternalMatchValidationType {
        match self {
            MatchValidationType::Aws(_) => InternalMatchValidationType::Aws,
            MatchValidationType::CustomHttp(http_config) => {
                InternalMatchValidationType::CustomHttp(http_config.endpoint.clone())
            }
        }
    }
}

// This is the match validation type stored in the compiled rule
// It is used to retrieve the MatchValidator. We don't need the full configuration for that purpose
// as it would be heavy to compute hash and compare the full configuration.
#[derive(PartialEq, Eq, Hash)]
pub enum InternalMatchValidationType {
    Aws,
    CustomHttp(String),
}
