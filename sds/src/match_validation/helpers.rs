use crate::{CustomHttpConfig, HttpStatusCodeRange};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpValidatorHelper;

/// Helper functions to create common HTTP validator configurations.
///
/// This module provides pre-configured HTTP validator settings for popular services
/// like GitHub and Datadog.
///
/// The configurations include appropriate endpoints, headers, and status code ranges
/// that indicate whether matches are valid or not.
///
/// # Examples
///
/// ```
/// use crate::match_validation::helpers::HttpValidatorHelper;
///
/// // Create GitHub API validator config
/// let github_config = HttpValidatorHelper::new_github_config();
///
/// // Create Datadog API validator config
/// let datadog_config = HttpValidatorHelper::new_datadog_config();
/// ```

impl HttpValidatorHelper {
    #[allow(dead_code)]
    pub fn new_github_config() -> CustomHttpConfig {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer $MATCH".to_string());
        headers.insert("User-Agent".to_string(), "TEST_DD_SDS".to_string());
        headers.insert("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string());

        CustomHttpConfig::default()
            .with_endpoint("https://api.github.com/octocat".to_string())
            .with_request_headers(headers)
            .with_invalid_http_status_code(vec![HttpStatusCodeRange {
                start: 401,
                end: 404,
            }])
            .with_valid_http_status_code(vec![HttpStatusCodeRange {
                start: 200,
                end: 300,
            }])
    }

    #[allow(dead_code)]
    pub fn new_datadog_config() -> CustomHttpConfig {
        let mut headers = BTreeMap::new();
        headers.insert("DD-API-KEY".to_string(), "$MATCH".to_string());
        headers.insert("User-Agent".to_string(), "TEST_DD_SDS".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());

        CustomHttpConfig::default()
            .with_endpoint("https://$HOST/api/v1/validate".to_string())
            .with_hosts(vec![
                "api.datadoghq.com".to_string(),
                "api.datadoghq.eu".to_string(),
                "api.us3.datadoghq.com".to_string(),
                "api.us5.datadoghq.com".to_string(),
                "api.ddog-gov.com".to_string(),
                "api.ap1.datadoghq.com".to_string(),
            ])
            .with_request_headers(headers)
            .with_invalid_http_status_code(vec![HttpStatusCodeRange {
                start: 403,
                end: 404,
            }])
            .with_valid_http_status_code(vec![HttpStatusCodeRange {
                start: 200,
                end: 300,
            }])
    }
}
