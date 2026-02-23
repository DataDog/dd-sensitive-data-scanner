use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    time::Duration,
};

use crate::{HttpMethod, RuleMatch};

/// Configuration for Online Validation V2
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct CustomHttpConfigV2 {
    /// Optional match pairing configuration for validating using matches from multiple rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_pairing: Option<MatchPairingConfig>,

    /// Array of HTTP calls to attempt. Only one needs to succeed for validation.
    pub calls: Vec<HttpCallConfig>,
}

impl CustomHttpConfigV2 {
    pub fn with_call(mut self, call: HttpCallConfig) -> Self {
        self.calls.push(call);
        self
    }
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

impl MatchPairingConfig {
    pub fn is_fulfilled_by(&self, template_variables: &[TemplateVariable]) -> bool {
        self.parameters.iter().all(|(_name, template_name)| {
            template_variables.iter().any(|v| v.name == *template_name)
        })
    }
}

/// A single HTTP call configuration with request and response validation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpCallConfig {
    pub request: HttpRequestConfig,
    pub response: HttpResponseConfig,
}

/// HTTP request configuration with templating support
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpRequestConfig {
    /// Endpoint URL with optional template variables
    /// Example: "https://$CLIENT_SUBDOMAIN.vendor.com/api/0/organizations/$MATCH"
    pub endpoint: TemplatedMatchString,

    #[serde(default = "default_http_method")]
    pub method: HttpMethod,

    /// Optional list of hosts for multi-datacenter support
    /// If specified, $HOST in endpoint will be replaced with each host
    #[serde(default)]
    pub hosts: Vec<String>,

    /// Request headers with template variable support
    /// Example: {"Authorization": "Basic %base64($CLIENT_ID:$MATCH)"}
    #[serde(default)]
    pub headers: BTreeMap<String, TemplatedMatchString>,

    /// Optional request body with template variable support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<TemplatedMatchString>,

    #[serde(default = "default_timeout")]
    pub timeout: Duration,
}

fn default_http_method() -> HttpMethod {
    HttpMethod::Get
}

fn default_timeout() -> Duration {
    Duration::from_secs(3)
}

/// Response validation configuration with multiple condition support
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpResponseConfig {
    /// Array of response conditions to check
    /// Conditions are evaluated sequentially until one matches
    pub conditions: Vec<ResponseCondition>,
}

/// A response condition that determines if a secret is valid or invalid
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
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

impl ResponseCondition {
    pub fn matches(&self, status_code: u16, body: &str) -> ResponseConditionResult {
        if let Some(status_code_matcher) = self.status_code.as_ref()
            && status_code_matcher.matches(status_code)
        {
            return self.condition_type.clone().into();
        }
        if let Some(raw_body_matcher) = self.raw_body.as_ref()
            && raw_body_matcher.matches(body)
        {
            return self.condition_type.clone().into();
        }
        ResponseConditionResult::NotChecked
    }
}

/// Type of response condition
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ResponseConditionType {
    Valid,
    Invalid,
}

#[derive(Debug, PartialEq)]
pub enum ResponseConditionResult {
    Valid,
    Invalid,
    NotChecked,
}

impl From<ResponseConditionType> for ResponseConditionResult {
    fn from(condition_type: ResponseConditionType) -> Self {
        match condition_type {
            ResponseConditionType::Valid => ResponseConditionResult::Valid,
            ResponseConditionType::Invalid => ResponseConditionResult::Invalid,
        }
    }
}

/// Status code matcher supporting single, list, or range
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "config")]
pub enum BodyMatcher {
    /// Check that the body/field is present (not null/undefined)
    Present,

    /// Check for exact string match
    ExactMatch(String),

    /// Check if the value matches a regex pattern
    Regex(String),
}

impl BodyMatcher {
    pub fn matches(&self, body: &str) -> bool {
        match self {
            BodyMatcher::Present => !body.is_empty(),
            BodyMatcher::ExactMatch(value) => body == *value,
            BodyMatcher::Regex(pattern) => regex::Regex::new(pattern).unwrap().is_match(body),
        }
    }
}

/// Secondary validator type for rules that forward their match to a paired validator
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PairedValidatorConfig {
    /// Vendor identifier to match the main validator
    pub kind: String,

    /// Name of the parameter this rule provides
    /// Example: "client_id", "client_subdomain"
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemplatedMatchString(pub String);

impl TemplatedMatchString {
    pub fn with_rule_match(&self, rule_match: &RuleMatch) -> Self {
        self.render("$MATCH", rule_match.match_value.as_ref().unwrap())
    }

    pub fn with_host(&self, host: &str) -> Self {
        self.render("$HOST", host)
    }

    pub fn with_template_variable(&self, template_variable: &TemplateVariable) -> Self {
        self.render(
            template_variable.name.as_str(),
            template_variable.value.as_str(),
        )
    }

    fn render(&self, tag: &str, value: &str) -> Self {
        TemplatedMatchString(self.0.replace(tag, value))
    }
}

impl Display for TemplatedMatchString {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemplateVariable {
    pub name: String,
    pub value: String,
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
    fn test_body_matcher_present() {
        let matcher = BodyMatcher::Present;
        assert!(matcher.matches("test"));
        assert!(!matcher.matches(""));
    }

    #[test]
    fn test_body_matcher_exact_match() {
        let matcher = BodyMatcher::ExactMatch("test".to_string());
        assert!(matcher.matches("test"));
        assert!(!matcher.matches("test1"));
        assert!(!matcher.matches(""));
    }

    #[test]
    fn test_body_matcher_regex() {
        let matcher = BodyMatcher::Regex("test".to_string());
        assert!(matcher.matches("test"));
        assert!(matcher.matches("test1"));
        assert!(!matcher.matches("different"));
    }
}
