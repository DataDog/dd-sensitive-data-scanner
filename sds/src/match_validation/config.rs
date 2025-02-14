use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{hash::Hash, ops::Range, time::Duration, vec};

use super::aws_validator::AwsValidator;
use super::http_validator::HttpValidator;
use super::match_validator::MatchValidator;

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
#[serde(tag = "kind")]
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
    pub endpoints: Vec<String>,
    pub method: HttpMethod,
    pub request_header: Vec<RequestHeader>,
    pub valid_http_status_code: Vec<Range<u16>>,
    pub invalid_http_status_code: Vec<Range<u16>>,
    pub options: HttpValidatorOption,
}

impl HttpValidatorConfig {
    fn new(endpoint: &str, hosts: Vec<String>) -> Result<Self, String> {
        // Handle errors cases
        // - endpoint contains $HOST but no hosts are provided
        // - endpoint does not contain $HOST but hosts are provided
        if endpoint.contains("$HOST") && hosts.is_empty() {
            return Err("Endpoint contains $HOST but no hosts are provided".to_string());
        }
        if !endpoint.contains("$HOST") && !hosts.is_empty() {
            return Err("Endpoint does not contain $HOST but hosts are provided".to_string());
        }

        // Replace $HOST in endpoint and build the endpoints vector
        let mut endpoints = vec![];
        for host in hosts {
            endpoints.push(endpoint.replace("$HOST", &host));
        }
        if endpoints.is_empty() {
            // If no hosts are provided, use the endpoint as is
            endpoints.push(endpoint.to_string());
        }
        Ok(HttpValidatorConfig {
            endpoints,
            method: HttpMethod::Get,
            request_header: vec![],
            #[allow(clippy::single_range_in_vec_init)]
            valid_http_status_code: vec![200..300],
            #[allow(clippy::single_range_in_vec_init)]
            invalid_http_status_code: vec![400..500],
            options: HttpValidatorOption {
                timeout: Duration::from_secs(DEFAULT_HTTPS_TIMEOUT_SEC),
            },
        })
    }
}

pub struct HttpValidatorConfigBuilder {
    endpoint: String,
    hosts: Vec<String>,
    method: HttpMethod,
    request_header: Vec<RequestHeader>,
    valid_http_status_code: Vec<Range<u16>>,
    invalid_http_status_code: Vec<Range<u16>>,
    options: HttpValidatorOption,
}

impl HttpValidatorConfigBuilder {
    pub fn new(endpoint: String) -> Self {
        HttpValidatorConfigBuilder {
            endpoint,
            hosts: vec![],
            method: HttpMethod::Get,
            request_header: vec![RequestHeader {
                key: "Authorization".to_string(),
                value: "Bearer $MATCH".to_string(),
            }],
            #[allow(clippy::single_range_in_vec_init)]
            valid_http_status_code: vec![200..300],
            #[allow(clippy::single_range_in_vec_init)]
            invalid_http_status_code: vec![400..500],
            options: HttpValidatorOption {
                timeout: Duration::from_secs(DEFAULT_HTTPS_TIMEOUT_SEC),
            },
        }
    }
    pub fn set_request_header(&mut self, request_header: Vec<RequestHeader>) -> &mut Self {
        self.request_header = request_header;
        self
    }
    pub fn set_hosts(&mut self, hosts: Vec<String>) -> &mut Self {
        self.hosts = hosts;
        self
    }
    pub fn set_method(&mut self, method: HttpMethod) -> &mut Self {
        self.method = method;
        self
    }
    pub fn set_valid_http_status_code(
        &mut self,
        valid_http_status_code: Vec<Range<u16>>,
    ) -> &mut Self {
        self.valid_http_status_code = valid_http_status_code;
        self
    }
    pub fn set_invalid_http_status_code(
        &mut self,
        invalid_http_status_code: Vec<Range<u16>>,
    ) -> &mut Self {
        self.invalid_http_status_code = invalid_http_status_code;
        self
    }
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.options.timeout = timeout;
        self
    }
    pub fn build(&self) -> Result<HttpValidatorConfig, String> {
        let mut config = HttpValidatorConfig::new(self.endpoint.as_str(), self.hosts.clone())?;
        config.invalid_http_status_code = self.invalid_http_status_code.clone();
        config.method = self.method.clone();
        config.request_header = self.request_header.clone();
        config.valid_http_status_code = self.valid_http_status_code.clone();
        config.options = self.options.clone();
        config.invalid_http_status_code = self.invalid_http_status_code.clone();
        Ok(config)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "config")]
pub enum MatchValidationType {
    Aws(AwsType),
    CustomHttp(HttpValidatorConfig),
}

impl MatchValidationType {
    // Method used to check if the validator can be created based on this type
    pub fn can_create_match_validator(&self) -> bool {
        match self {
            MatchValidationType::Aws(aws_type) => matches!(aws_type, AwsType::AwsSecret(_)),
            MatchValidationType::CustomHttp(_) => true,
        }
    }
    pub fn get_internal_match_validation_type(&self) -> InternalMatchValidationType {
        match self {
            MatchValidationType::Aws(_) => InternalMatchValidationType::Aws,
            MatchValidationType::CustomHttp(http_config) => {
                InternalMatchValidationType::CustomHttp(http_config.endpoints.clone())
            }
        }
    }
    pub fn into_match_validator(&self) -> Result<Box<dyn MatchValidator>, String> {
        match self {
            MatchValidationType::Aws(aws_type) => match aws_type {
                AwsType::AwsSecret(aws_config) => {
                    Ok(Box::new(AwsValidator::new(aws_config.clone())))
                }
                _ => Err("This aws type shall not be used to create a validator".to_string()),
            },
            MatchValidationType::CustomHttp(http_config) => Ok(Box::new(
                HttpValidator::new_from_config(http_config.clone()),
            )),
        }
    }
}

// This is the match validation type stored in the compiled rule
// It is used to retrieve the MatchValidator. We don't need the full configuration for that purpose
// as it would be heavy to compute hash and compare the full configuration.
#[derive(PartialEq, Eq, Hash)]
pub enum InternalMatchValidationType {
    Aws,
    CustomHttp(Vec<String>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_validator_config_no_hosts() {
        let config = HttpValidatorConfig::new("http://localhost/test", vec![]).unwrap();
        assert_eq!(config.endpoints, vec!["http://localhost/test"]);
    }

    #[test]
    fn test_http_validator_config_with_hosts() {
        let config = HttpValidatorConfig::new(
            "http://localhost/$HOST",
            vec!["us".to_string(), "eu".to_string()],
        )
        .unwrap();
        assert_eq!(
            config.endpoints,
            vec!["http://localhost/us", "http://localhost/eu"]
        );
    }

    #[test]
    fn test_http_validator_config_error_cases() {
        let config = HttpValidatorConfig::new("http://localhost/$HOST", vec![]).unwrap_err();
        assert_eq!(
            config,
            "Endpoint contains $HOST but no hosts are provided".to_string()
        );
    }

    #[test]
    fn test_http_validator_config_error_cases_with_hosts() {
        let config =
            HttpValidatorConfig::new("http://localhost/test", vec!["us".to_string()]).unwrap_err();
        assert_eq!(
            config,
            "Endpoint does not contain $HOST but hosts are provided".to_string()
        );
    }
    #[test]
    fn test_http_validator_builder_config_no_hosts() {
        let config = HttpValidatorConfigBuilder::new("http://localhost/test".to_string())
            .build()
            .unwrap();
        assert_eq!(config.endpoints, vec!["http://localhost/test"]);
    }

    #[test]
    fn test_http_validator_builder_config_with_hosts() {
        let config = HttpValidatorConfigBuilder::new("http://localhost/$HOST".to_string())
            .set_hosts(vec!["us".to_string(), "eu".to_string()])
            .build()
            .unwrap();
        assert_eq!(
            config.endpoints,
            vec!["http://localhost/us", "http://localhost/eu"]
        );
    }
}
