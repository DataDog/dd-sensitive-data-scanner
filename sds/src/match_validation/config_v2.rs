use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};

/// Configuration for Online Validation V2
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CustomHttpConfigV2 {
    /// Optional match pairing configuration for validating using matches from multiple rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_pairing: Option<MatchPairingConfig>,

    /// Array of HTTP calls to attempt. Only one needs to succeed for validation.
    pub calls: Vec<HttpCallConfig>,
}

/// Configuration for pairing matches from multiple rules together
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MatchPairingConfig {
    /// Vendor identifier to match across rules.
    pub kind: String,

    /// Map of parameter names to template variables
    #[serde(flatten)]
    pub parameters: BTreeMap<String, String>,
}

/// A single HTTP call configuration with request and response validation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HttpCallConfig {
    pub request: HttpRequestConfig,
    pub response: HttpResponseConfig,
}

/// HTTP request configuration with templating support
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HttpRequestConfig {
    /// Endpoint URL with optional template variables
    /// Example: "https://$CLIENT_SUBDOMAIN.vendor.com/api/0/organizations/$MATCH"
    pub endpoint: String,

    #[serde(default = "default_http_method")]
    pub method: String,

    /// Optional list of hosts for multi-datacenter support
    /// If specified, $HOST in endpoint will be replaced with each host
    #[serde(default)]
    pub hosts: Vec<String>,

    /// Request headers with template variable support
    /// Example: {"Authorization": "Basic %base64($CLIENT_ID:$MATCH)"}
    #[serde(default)]
    pub headers: BTreeMap<String, String>,

    /// Optional request body with template variable support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,

    #[serde(default = "default_timeout_seconds")]
    pub timeout: Duration,
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_timeout_seconds() -> Duration {
    Duration::from_secs(3)
}

/// Response validation configuration with multiple condition support
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HttpResponseConfig {
    /// Array of response conditions to check
    /// Conditions are evaluated sequentially until one matches
    pub conditions: Vec<ResponseCondition>,
}

/// A response condition that determines if a secret is valid or invalid
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ResponseCondition {
    /// Whether this condition indicates a valid or invalid secret
    #[serde(rename = "type")]
    pub condition_type: ResponseConditionType,

    /// Optional status code matcher
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<StatusCodeMatcher>,

    /// Optional raw body matcher (before parsing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<BodyMatcher>,

    /// Optional parsed body matchers (after JSON parsing)
    /// Maps JSON paths to matchers
    /// Example: {"message.stack[2].success.status": BodyMatcher}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<BTreeMap<String, BodyMatcher>>,
}

/// Type of response condition
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResponseConditionType {
    Valid,
    Invalid,
}

/// Status code matcher supporting single, list, or range
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum StatusCodeMatcher {
    /// Single status code: 200
    Single(u16),

    /// List of status codes: [401, 403, 404]
    List(Vec<u16>),

    /// Range of status codes: {"start": 400, "end": 420}
    Range { start: u16, end: u16 },
}

impl StatusCodeMatcher {
    /// Check if a status code matches this matcher
    pub fn matches(&self, status_code: u16) -> bool {
        match self {
            StatusCodeMatcher::Single(code) => status_code == *code,
            StatusCodeMatcher::List(codes) => codes.contains(&status_code),
            StatusCodeMatcher::Range { start, end } => status_code >= *start && status_code < *end,
        }
    }
}

/// Body content matcher
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "config")]
pub enum BodyMatcher {
    /// Check that the body/field is present (not null/undefined)
    Present,

    /// Check for exact string match
    ExactMatch(String),

    /// Check if the value matches a regex pattern
    Regex(String),
}

/// Secondary validator type for rules that forward their match to a paired validator
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PairedValidatorConfig {
    /// Vendor identifier to match the main validator
    pub kind: String,

    /// Name of the parameter this rule provides
    /// Example: "client_id", "client_subdomain"
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_matcher_single() {
        let matcher = StatusCodeMatcher::Single(200);
        assert!(matcher.matches(200));
        assert!(!matcher.matches(201));
        assert!(!matcher.matches(404));
    }

    #[test]
    fn test_status_code_matcher_list() {
        let matcher = StatusCodeMatcher::List(vec![200, 201, 204]);
        assert!(matcher.matches(200));
        assert!(matcher.matches(201));
        assert!(matcher.matches(204));
        assert!(!matcher.matches(202));
        assert!(!matcher.matches(404));
    }

    #[test]
    fn test_status_code_matcher_range() {
        let matcher = StatusCodeMatcher::Range {
            start: 200,
            end: 300,
        };
        assert!(matcher.matches(200));
        assert!(matcher.matches(250));
        assert!(matcher.matches(299));
        assert!(!matcher.matches(199));
        assert!(!matcher.matches(300));
        assert!(!matcher.matches(404));
    }

    #[test]
    fn test_deserialize_simple_config() {
        let json = r#"{
            "calls": [
                {
                    "request": {
                        "endpoint": "https://api.example.com/validate",
                        "method": "GET",
                        "headers": {
                            "Authorization": "Bearer $MATCH"
                        }
                    },
                    "response": {
                        "conditions": [
                            {
                                "type": "valid",
                                "status_code": 200
                            },
                            {
                                "type": "invalid",
                                "status_code": {"start": 400, "end": 500}
                            }
                        ]
                    }
                }
            ]
        }"#;

        let config: CustomHttpConfigV2 = serde_json::from_str(json).unwrap();
        assert_eq!(config.calls.len(), 1);
        assert_eq!(
            config.calls[0].request.endpoint,
            "https://api.example.com/validate"
        );
        assert_eq!(config.calls[0].request.method, "GET");
        assert_eq!(config.calls[0].response.conditions.len(), 2);
    }

    #[test]
    fn test_deserialize_with_match_pairing() {
        let json = r#"{
            "match_pairing": {
                "kind": "vendorX",
                "client_subdomain": "$CLIENT_SUBDOMAIN",
                "client_id": "$CLIENT_ID"
            },
            "calls": [
                {
                    "request": {
                        "endpoint": "https://$CLIENT_SUBDOMAIN.vendor.com/api/0/organizations/$MATCH",
                        "method": "POST",
                        "headers": {
                            "Authorization": "Basic %base64($CLIENT_ID:$MATCH)"
                        },
                        "request_body": "{\"key\": \"value\"}"
                    },
                    "response": {
                        "conditions": [
                            {
                                "type": "valid",
                                "status_code": 200,
                                "raw_body": {
                                    "type": "Present"
                                }
                            }
                        ]
                    }
                }
            ]
        }"#;

        let config: CustomHttpConfigV2 = serde_json::from_str(json).unwrap();
        assert!(config.match_pairing.is_some());
        let pairing = config.match_pairing.unwrap();
        assert_eq!(pairing.kind, "vendorX");
        assert_eq!(pairing.parameters.len(), 2);
        assert_eq!(
            pairing.parameters.get("client_subdomain"),
            Some(&"$CLIENT_SUBDOMAIN".to_string())
        );
        assert_eq!(
            pairing.parameters.get("client_id"),
            Some(&"$CLIENT_ID".to_string())
        );
    }

    #[test]
    fn test_deserialize_with_body_matchers() {
        let json = r#"{
            "calls": [
                {
                    "request": {
                        "endpoint": "https://api.example.com/validate",
                        "method": "POST"
                    },
                    "response": {
                        "conditions": [
                            {
                                "type": "valid",
                                "status_code": [200, 201, 204]
                            },
                            {
                                "type": "valid",
                                "status_code": 403,
                                "body": {
                                    "message.stack[2].success.status": {
                                        "type": "Regex",
                                        "config": "^2\\d\\d"
                                    }
                                }
                            },
                            {
                                "type": "invalid",
                                "status_code": {"start": 400, "end": 412},
                                "raw_body": {
                                    "type": "ExactMatch",
                                    "config": "Unknown Token"
                                }
                            }
                        ]
                    }
                }
            ]
        }"#;

        let config: CustomHttpConfigV2 = serde_json::from_str(json).unwrap();
        assert_eq!(config.calls[0].response.conditions.len(), 3);

        // Check first condition (list of status codes)
        let cond1 = &config.calls[0].response.conditions[0];
        assert_eq!(cond1.condition_type, ResponseConditionType::Valid);
        if let Some(StatusCodeMatcher::List(codes)) = &cond1.status_code {
            assert_eq!(codes, &vec![200, 201, 204]);
        } else {
            panic!("Expected list status code matcher");
        }

        // Check second condition (with body matcher)
        let cond2 = &config.calls[0].response.conditions[1];
        assert!(cond2.body.is_some());

        // Check third condition (with raw_body matcher)
        let cond3 = &config.calls[0].response.conditions[2];
        assert!(cond3.raw_body.is_some());
    }

    #[test]
    fn test_deserialize_paired_validator_config() {
        let json = r#"{
            "kind": "vendorX",
            "name": "client_id"
        }"#;

        let config: PairedValidatorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.kind, "vendorX");
        assert_eq!(config.name, "client_id");
    }

    #[test]
    fn test_deserialize_multiple_calls() {
        let json = r#"{
            "calls": [
                {
                    "request": {
                        "endpoint": "https://api.example.com/v1/validate"
                    },
                    "response": {
                        "conditions": [
                            {"type": "valid", "status_code": 200}
                        ]
                    }
                },
                {
                    "request": {
                        "endpoint": "https://api.example.com/v2/validate"
                    },
                    "response": {
                        "conditions": [
                            {"type": "valid", "status_code": 200}
                        ]
                    }
                }
            ]
        }"#;

        let config: CustomHttpConfigV2 = serde_json::from_str(json).unwrap();
        assert_eq!(config.calls.len(), 2);
        assert_eq!(
            config.calls[0].request.endpoint,
            "https://api.example.com/v1/validate"
        );
        assert_eq!(
            config.calls[1].request.endpoint,
            "https://api.example.com/v2/validate"
        );
    }

    #[test]
    fn test_serialize_and_deserialize() {
        let config = CustomHttpConfigV2 {
            match_pairing: Some(MatchPairingConfig {
                kind: "test_vendor".to_string(),
                parameters: [
                    ("client_id".to_string(), "$CLIENT_ID".to_string()),
                    ("subdomain".to_string(), "$SUBDOMAIN".to_string()),
                ]
                .into(),
            }),
            calls: vec![HttpCallConfig {
                request: HttpRequestConfig {
                    endpoint: "https://$SUBDOMAIN.example.com/api".to_string(),
                    method: "POST".to_string(),
                    hosts: vec![],
                    headers: [("Authorization".to_string(), "Bearer $MATCH".to_string())].into(),
                    request_body: Some("{\"test\": true}".to_string()),
                    timeout_seconds: 5,
                },
                response: HttpResponseConfig {
                    conditions: vec![
                        ResponseCondition {
                            condition_type: ResponseConditionType::Valid,
                            status_code: Some(StatusCodeMatcher::Single(200)),
                            raw_body: None,
                            body: None,
                        },
                        ResponseCondition {
                            condition_type: ResponseConditionType::Invalid,
                            status_code: Some(StatusCodeMatcher::Range {
                                start: 400,
                                end: 500,
                            }),
                            raw_body: None,
                            body: None,
                        },
                    ],
                },
            }],
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: CustomHttpConfigV2 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }
}
