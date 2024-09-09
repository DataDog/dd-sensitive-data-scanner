use super::{config::HttpValidatorConfig, match_validator::MatchValidator};
use crate::{match_validation::config::HttpMethod, CompiledRuleDyn, MatchStatus, RuleMatch};
use async_trait::async_trait;
use futures::future::join_all;
use reqwest::Client;
use std::fmt;

pub struct HttpValidator {
    config: HttpValidatorConfig,
}

impl HttpValidator {
    pub fn new(config: HttpValidatorConfig) -> Self {
        HttpValidator { config }
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
                            &header.get_value_with_match(m.matched_string.as_ref().unwrap()),
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
