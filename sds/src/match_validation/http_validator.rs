use super::{
    config::{self, HttpValidatorConfig, HttpValidatorOption, RequestHeader},
    match_validator::MatchValidator,
};
use crate::{match_validation::config::HttpMethod, CompiledRuleDyn, MatchStatus, RuleMatch};
use async_trait::async_trait;
use futures::future::join_all;
use reqwest::Client;
use std::{fmt, ops::Range, time::Duration};

pub struct HttpValidator {
    config: HttpValidatorConfig,
}

impl HttpValidator {
    pub fn new(config: HttpValidatorConfig) -> Self {
        HttpValidator { config }
    }
}

pub struct HttpValidatorConfigBuilder {
    endpoint: String,
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
            method: HttpMethod::Get,
            request_header: vec![RequestHeader {
                key: "Authorization".to_string(),
                value: "Bearer $MATCH".to_string(),
            }],
            valid_http_status_code: vec![200..300],
            invalid_http_status_code: vec![400..500],
            options: HttpValidatorOption {
                timeout: Duration::from_secs(config::DEFAULT_HTTPS_TIMEOUT_SEC),
            },
        }
    }
    pub fn set_request_header(&mut self, request_header: Vec<RequestHeader>) -> &mut Self {
        self.request_header = request_header;
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
    pub fn build(&self) -> HttpValidatorConfig {
        HttpValidatorConfig {
            endpoint: self.endpoint.clone(),
            method: self.method.clone(),
            request_header: self.request_header.clone(),
            valid_http_status_code: self.valid_http_status_code.clone(),
            invalid_http_status_code: self.invalid_http_status_code.clone(),
            options: self.options.clone(),
        }
    }
}

pub struct HttpValidatorHelper;

impl HttpValidatorHelper {
    pub fn new_github_config_builder() -> HttpValidatorConfigBuilder {
        let mut builder =
            HttpValidatorConfigBuilder::new("https://api.github.com/octocat".to_string());
        builder.set_request_header(vec![
            RequestHeader {
                key: "Authorization".to_string(),
                value: "Bearer $MATCH".to_string(),
            },
            RequestHeader {
                key: "User-Agent".to_string(),
                value: "TEST_DD_SDS".to_string(),
            },
            RequestHeader {
                key: "X-GitHub-Api-Version".to_string(),
                value: "2022-11-28".to_string(),
            },
        ]);
        builder
    }

    pub fn new_datadog_config_builder() -> HttpValidatorConfigBuilder {
        let mut builder = HttpValidatorConfigBuilder::new(
            "https://api.datadoghq.com/api/v1/validate".to_string(),
        );
        builder.set_request_header(vec![
            RequestHeader {
                key: "DD-API-KEY".to_string(),
                value: "$MATCH".to_string(),
            },
            RequestHeader {
                key: "User-Agent".to_string(),
                value: "TEST_DD_SDS".to_string(),
            },
            RequestHeader {
                key: "Accept".to_string(),
                value: "application/json".to_string(),
            },
        ]);
        builder
    }
}

#[async_trait]
impl MatchValidator for HttpValidator {
    async fn validate(&self, matches: &mut Vec<RuleMatch>, _: &Vec<Box<dyn CompiledRuleDyn>>) {
        // Let's reqwest the HTTP API endpoint to validate the matches
        let client = Client::new();
        let futures = matches
            .iter_mut()
            .map(|m| {
                let client = client.clone();
                async move {
                    let mut request_builder: reqwest::RequestBuilder;
                    match self.config.method {
                        HttpMethod::Get => {
                            request_builder = client.get(&self.config.endpoint);
                        }
                        HttpMethod::Post => {
                            request_builder = client.post(&self.config.endpoint);
                        }
                        HttpMethod::Put => {
                            request_builder = client.put(&self.config.endpoint);
                        }
                        HttpMethod::Delete => {
                            request_builder = client.delete(&self.config.endpoint);
                        }
                        HttpMethod::Patch => {
                            request_builder = client.patch(&self.config.endpoint);
                        }
                    }
                    // Set timeout
                    request_builder = request_builder.timeout(self.config.options.timeout);

                    // Add headers
                    for header in &self.config.request_header {
                        request_builder = request_builder.header(
                            &header.key,
                            &header.get_value_with_match(m.match_value.as_ref().unwrap()),
                        );
                    }
                    let res = request_builder.send().await;
                    match res {
                        Ok(val) => {
                            // First check if this is in the valid status ranges
                            for valid_range in &self.config.valid_http_status_code {
                                if valid_range.contains(&val.status().as_u16()) {
                                    m.match_status = MatchStatus::Valid;
                                    return;
                                }
                            }
                            // Next check if this is in the invalid status ranges
                            for invalid_range in &self.config.invalid_http_status_code {
                                if invalid_range.contains(&val.status().as_u16()) {
                                    m.match_status = MatchStatus::Invalid;
                                    return;
                                }
                            }
                            // If it's not in either, then it's not available
                            m.match_status = MatchStatus::Error(fmt::format(format_args!(
                                "Unexpected HTTP status code {}",
                                val.status().as_u16()
                            )));
                        }
                        Err(err) => {
                            // TODO(trosenblatt) emit a metrics for this
                            m.match_status = MatchStatus::Error(fmt::format(format_args!(
                                "Error making HTTP request: {}",
                                err
                            )));
                        }
                    }
                }
            })
            .collect::<Vec<_>>();

        // Wait for all result to complete
        let _ = join_all(futures).await;
    }
}
