use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::{hash::Hash, time::Duration};

use super::aws_validator::AwsValidator;
use super::http_validator::HttpValidator;
use super::match_validator::MatchValidator;

pub const DEFAULT_HTTPS_TIMEOUT_SEC: u64 = 3;
pub const DEFAULT_AWS_STS_ENDPOINT: &str = "https://sts.amazonaws.com";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AwsConfig {
    // Override default AWS STS endpoint for testing
    #[serde(default = "default_aws_sts_endpoint")]
    pub aws_sts_endpoint: String,
    // Override default datetime for testing
    pub forced_datetime_utc: Option<DateTime<Utc>>,
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
}

fn default_aws_sts_endpoint() -> String {
    DEFAULT_AWS_STS_ENDPOINT.to_string()
}

fn default_timeout() -> Duration {
    Duration::from_secs(DEFAULT_HTTPS_TIMEOUT_SEC)
}

impl Default for AwsConfig {
    fn default() -> Self {
        AwsConfig {
            aws_sts_endpoint: default_aws_sts_endpoint(),
            forced_datetime_utc: None,
            timeout: default_timeout(),
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
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl FromStr for HttpMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "PATCH" => Ok(HttpMethod::Patch),
            _ => Err(format!("Invalid HTTP method: {}", s)),
        }
    }
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
pub struct CustomHttpConfig {
    pub endpoint: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default = "default_http_method")]
    pub http_method: HttpMethod,
    pub request_headers: BTreeMap<String, String>,
    #[serde(default = "default_valid_http_status_code")]
    pub valid_http_status_code: Vec<HttpStatusCodeRange>,
    #[serde(default = "default_invalid_http_status_code")]
    pub invalid_http_status_code: Vec<HttpStatusCodeRange>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u32,
}

impl Default for CustomHttpConfig {
    fn default() -> Self {
        CustomHttpConfig {
            endpoint: "".to_string(),
            hosts: vec![],
            http_method: HttpMethod::Get,
            request_headers: BTreeMap::new(),
            valid_http_status_code: vec![],
            invalid_http_status_code: vec![],
            timeout_seconds: DEFAULT_HTTPS_TIMEOUT_SEC as u32,
        }
    }
}

impl CustomHttpConfig {
    pub fn get_endpoints(&self) -> Result<Vec<String>, String> {
        // Handle errors cases
        // - endpoint contains $HOST but no hosts are provided
        // - endpoint does not contain $HOST but hosts are provided
        if self.endpoint.contains("$HOST") && self.hosts.is_empty() {
            return Err("Endpoint contains $HOST but no hosts are provided".to_string());
        }
        if !self.endpoint.contains("$HOST") && !self.hosts.is_empty() {
            return Err("Endpoint does not contain $HOST but hosts are provided".to_string());
        }

        // Replace $HOST in endpoint and build the endpoints vector
        let mut endpoints = vec![];
        for host in self.hosts.clone() {
            endpoints.push(self.endpoint.replace("$HOST", &host));
        }
        if endpoints.is_empty() {
            // If no hosts are provided, use the endpoint as is
            endpoints.push(self.endpoint.to_string());
        }
        Ok(endpoints)
    }

    // Builders

    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }

    pub fn with_hosts(mut self, hosts: Vec<String>) -> Self {
        self.hosts = hosts;
        self
    }

    pub fn with_request_headers(mut self, request_headers: BTreeMap<String, String>) -> Self {
        self.request_headers = request_headers;
        self
    }

    pub fn with_valid_http_status_code(
        mut self,
        valid_http_status_code: Vec<HttpStatusCodeRange>,
    ) -> Self {
        self.valid_http_status_code = valid_http_status_code;
        self
    }

    pub fn with_invalid_http_status_code(
        mut self,
        invalid_http_status_code: Vec<HttpStatusCodeRange>,
    ) -> Self {
        self.invalid_http_status_code = invalid_http_status_code;
        self
    }

    // Setters

    pub fn set_endpoint(&mut self, endpoint: String) {
        self.endpoint = endpoint;
    }

    pub fn set_hosts(&mut self, hosts: Vec<String>) {
        self.hosts = hosts;
    }

    pub fn set_http_method(&mut self, http_method: HttpMethod) {
        self.http_method = http_method;
    }

    pub fn set_request_headers(&mut self, request_headers: BTreeMap<String, String>) {
        self.request_headers = request_headers;
    }

    pub fn set_valid_http_status_code(&mut self, valid_http_status_code: Vec<HttpStatusCodeRange>) {
        self.valid_http_status_code = valid_http_status_code;
    }

    pub fn set_invalid_http_status_code(
        &mut self,
        invalid_http_status_code: Vec<HttpStatusCodeRange>,
    ) {
        self.invalid_http_status_code = invalid_http_status_code;
    }

    pub fn set_timeout_seconds(&mut self, timeout_seconds: u32) {
        self.timeout_seconds = timeout_seconds;
    }
}

fn default_timeout_seconds() -> u32 {
    DEFAULT_HTTPS_TIMEOUT_SEC as u32
}

fn default_http_method() -> HttpMethod {
    HttpMethod::Get
}

fn default_valid_http_status_code() -> Vec<HttpStatusCodeRange> {
    vec![HttpStatusCodeRange {
        start: 200,
        end: 300,
    }]
}

fn default_invalid_http_status_code() -> Vec<HttpStatusCodeRange> {
    vec![HttpStatusCodeRange {
        start: 400,
        end: 500,
    }]
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HttpStatusCodeRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "config")]
pub enum MatchValidationType {
    Aws(AwsType),
    CustomHttp(CustomHttpConfig),
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
                InternalMatchValidationType::CustomHttp(http_config.get_endpoints().unwrap())
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
