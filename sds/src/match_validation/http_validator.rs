use super::{
    config::{HttpValidatorConfig, HttpValidatorConfigBuilder, RequestHeader},
    match_validator::MatchValidator,
};
use crate::{match_validation::config::HttpMethod, CompiledRuleDyn, MatchStatus, RuleMatch};
use ahash::AHashMap;
use async_trait::async_trait;
use futures::future::join_all;
use lazy_static::lazy_static;
use reqwest::Client;
use std::fmt;

lazy_static! {
    static ref HTTP_CLIENT: Client = Client::new();
}

pub struct HttpValidator {
    config: HttpValidatorConfig,
}

impl HttpValidator {
    pub fn new_clone_config(config: &HttpValidatorConfig) -> Self {
        HttpValidator {
            config: config.clone(),
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
        let mut builder =
            HttpValidatorConfigBuilder::new("https://$HOST/api/v1/validate".to_string());
        builder.set_hosts(vec![
            "api.datadoghq.com".to_string(),
            "api.datadoghq.eu".to_string(),
            "api.us3.datadoghq.com".to_string(),
            "api.us5.datadoghq.com".to_string(),
            "api.ddog-gov.com".to_string(),
            "api.ap1.datadoghq.com".to_string(),
        ]);
        #[allow(clippy::single_range_in_vec_init)]
        builder.set_invalid_http_status_code(vec![403..404]);
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
    async fn validate(&self, matches: &mut Vec<RuleMatch>, _: &[Box<dyn CompiledRuleDyn>]) {
        // build a map of match status per endpoint and per match_idx
        let mut match_status_per_endpoint_and_match: AHashMap<_, _> = matches
            .iter()
            .enumerate()
            .flat_map(|(idx, _)| {
                self.config
                    .endpoints
                    .iter()
                    .map(move |endpoint| ((idx, endpoint), MatchStatus::NotChecked))
            })
            .collect();

        let futures = match_status_per_endpoint_and_match.iter_mut().map(
            |((match_idx, endpoint), match_status)| {
                let match_value = matches[*match_idx].match_value.as_ref().unwrap();
                async move {
                    let mut request_builder = match self.config.method {
                        HttpMethod::Get => HTTP_CLIENT.get(*endpoint),
                        HttpMethod::Post => HTTP_CLIENT.post(*endpoint),
                        HttpMethod::Put => HTTP_CLIENT.put(*endpoint),
                        HttpMethod::Delete => HTTP_CLIENT.delete(*endpoint),
                        HttpMethod::Patch => HTTP_CLIENT.patch(*endpoint),
                    };
                    request_builder = request_builder.timeout(self.config.options.timeout);

                    // Add headers
                    for header in &self.config.request_header {
                        request_builder = request_builder
                            .header(&header.key, &header.get_value_with_match(match_value));
                    }
                    let res = request_builder.send().await;
                    match res {
                        Ok(val) => {
                            // First check if this is in the valid status ranges
                            for valid_range in &self.config.valid_http_status_code {
                                if valid_range.contains(&val.status().as_u16()) {
                                    *match_status = MatchStatus::Valid;
                                    return;
                                }
                            }
                            // Next check if this is in the invalid status ranges
                            for invalid_range in &self.config.invalid_http_status_code {
                                if invalid_range.contains(&val.status().as_u16()) {
                                    *match_status = MatchStatus::Invalid;
                                    return;
                                }
                            }
                            // If it's not in either, then it's not available
                            *match_status = MatchStatus::Error(fmt::format(format_args!(
                                "Unexpected HTTP status code {}",
                                val.status().as_u16()
                            )));
                        }
                        Err(err) => {
                            // TODO(trosenblatt) emit a metrics for this
                            *match_status = MatchStatus::Error(fmt::format(format_args!(
                                "Error making HTTP request: {}",
                                err
                            )));
                        }
                    }
                }
            },
        );
        // Wait for all result to complete
        let _ = join_all(futures).await;

        // Update the match status with this highest priority returned
        for ((match_idx, _), status) in match_status_per_endpoint_and_match {
            matches[match_idx].match_status.merge(status.clone());
        }
    }
}
