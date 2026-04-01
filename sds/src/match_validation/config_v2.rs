use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    time::Duration,
};

use crate::HttpMethod;

/// Configuration for Online Validation V2
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct CustomHttpConfigV2 {
    /// Optional match pairing configuration for validating using matches from multiple rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_pairing: Option<MatchPairingConfig>,

    /// Optional list of values this rule provides to other paired validators.
    /// Allows a rule to both self-validate with CustomHttpV2 and contribute its
    /// match value as named template variables to other CustomHttpV2 rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provides: Option<Vec<PairedValidatorConfig>>,

    /// Array of HTTP calls to attempt. Only one needs to succeed for validation.
    #[serde(default)]
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

    pub method: HttpMethod,

    /// Optional list of templated hosts for multi-datacenter support
    /// If specified, $HOST in endpoint will be replaced with each host
    #[serde(default)]
    pub hosts: Vec<TemplatedMatchString>,

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
    /// Example: {"$.message.stack[2].success.status": BodyMatcher}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<BTreeMap<String, BodyMatcher>>,
}

impl ResponseCondition {
    /// Determines if a ResponseCondition matches a given status code and body
    /// It does this by checking against each of the optional conditions and aggregating the results.
    ///
    /// Consider the example of a ResponseCondition with the following conditions:
    /// - status_code: 200
    /// - raw_body: "success"
    ///
    /// If the status code is 200, the raw body is "success", ResponseCondition matches.
    /// If the status code is 200, the raw body is "failure", then the ResponseCondition does not match.
    ///
    /// What happens next depends on the ResponseConditionType and whether or not the condition matched:
    /// * Matched and Invalid -> Invalid
    /// * Matched and Valid -> Valid
    /// * Not matched -> NotChecked
    pub fn matches(&self, status_code: u16, body: &str) -> ResponseConditionResult {
        if let Some(status_code_matcher) = self.status_code.as_ref()
            && !status_code_matcher.matches(status_code)
        {
            ResponseConditionResult::NotChecked
        } else if let Some(raw_body_matcher) = self.raw_body.as_ref()
            && !raw_body_matcher.matches(body)
        {
            ResponseConditionResult::NotChecked
        } else if let Some(body_matcher) = self.body.as_ref()
            && !matches_body(body_matcher, body)
        {
            ResponseConditionResult::NotChecked
        } else {
            self.condition_type.into()
        }
    }
}

fn matches_body(body_matcher: &BTreeMap<String, BodyMatcher>, body: &str) -> bool {
    let parsed_body: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return false,
    };
    for (path, matcher) in body_matcher.iter() {
        let Some(value) = get_json_path_value(&parsed_body, path) else {
            continue;
        };
        let value_str = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if matcher.matches(&value_str) {
            return true;
        }
    }
    false
}

/// Get the value at a given JSONPath
///
/// Simple parser as we don't need extensive JSONPath support and can thus avoid
/// pulling in a heavy JSONPath library.
fn get_json_path_value<'a>(
    root: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut cursor = path;
    let mut value = root;

    if let Some(remaining) = cursor.strip_prefix('$') {
        cursor = remaining;
    }

    if cursor.is_empty() {
        return Some(value);
    }

    while !cursor.is_empty() {
        if let Some(remaining) = cursor.strip_prefix('.') {
            let segment_end = remaining.find(['.', '[']).unwrap_or(remaining.len());
            if segment_end == 0 {
                return None;
            }
            let key = &remaining[..segment_end];
            value = value.get(key)?;
            cursor = &remaining[segment_end..];
            continue;
        }

        if let Some(remaining) = cursor.strip_prefix('[') {
            let closing_bracket = remaining.find(']')?;
            let segment = &remaining[..closing_bracket];
            value = if let Ok(index) = segment.parse::<usize>() {
                value.get(index)?
            } else {
                let quoted_key = segment
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| {
                        segment
                            .strip_prefix('\'')
                            .and_then(|s| s.strip_suffix('\''))
                    })?;
                value.get(quoted_key)?
            };
            cursor = &remaining[closing_bracket + 1..];
            continue;
        }

        let segment_end = cursor.find(['.', '[']).unwrap_or(cursor.len());
        if segment_end == 0 {
            return None;
        }
        let key = &cursor[..segment_end];
        value = value.get(key)?;
        cursor = &cursor[segment_end..];
    }

    Some(value)
}

/// Used for validating the body matcher path syntax
pub fn is_valid_body_matcher_path(path: &str) -> bool {
    let mut cursor = path;

    if let Some(remaining) = cursor.strip_prefix('$') {
        cursor = remaining;
    }

    if cursor.is_empty() {
        return true;
    }

    while !cursor.is_empty() {
        if let Some(remaining) = cursor.strip_prefix('.') {
            let segment_end = remaining.find(['.', '[']).unwrap_or(remaining.len());
            if segment_end == 0 {
                return false;
            }
            cursor = &remaining[segment_end..];
            continue;
        }

        if let Some(remaining) = cursor.strip_prefix('[') {
            let Some(closing_bracket) = remaining.find(']') else {
                return false;
            };
            let segment = &remaining[..closing_bracket];
            let is_valid_segment = segment.parse::<usize>().is_ok()
                || segment
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .is_some()
                || segment
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
                    .is_some();
            if !is_valid_segment {
                return false;
            }
            cursor = &remaining[closing_bracket + 1..];
            continue;
        }

        let segment_end = cursor.find(['.', '[']).unwrap_or(cursor.len());
        if segment_end == 0 {
            return false;
        }
        cursor = &cursor[segment_end..];
    }

    true
}

/// Type of response condition
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Copy)]
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
    // pub fn with_rule_match(&self, rule_match: &RuleMatch) -> Self {
    //     self.render("$MATCH", rule_match.match_value.as_ref().unwrap())
    // }

    // pub fn with_host(&self, host: &str) -> Self {
    //     self.render("$HOST", host)
    // }

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

    fn valid_condition_with_status_and_raw_body(
        status: StatusCodeMatcher,
        raw_body: BodyMatcher,
    ) -> ResponseCondition {
        ResponseCondition {
            condition_type: ResponseConditionType::Valid,
            status_code: Some(status),
            raw_body: Some(raw_body),
            body: None,
        }
    }

    // status_code + raw_body: all four combinations of match/miss

    #[test]
    fn test_condition_status_and_raw_body_both_match_returns_valid() {
        let cond = valid_condition_with_status_and_raw_body(
            StatusCodeMatcher::Single(200),
            BodyMatcher::ExactMatch("ok".to_string()),
        );
        assert_eq!(cond.matches(200, "ok"), ResponseConditionResult::Valid);
    }

    #[test]
    fn test_condition_status_matches_raw_body_does_not_returns_not_checked() {
        let cond = valid_condition_with_status_and_raw_body(
            StatusCodeMatcher::Single(200),
            BodyMatcher::ExactMatch("ok".to_string()),
        );
        // status matches but body does not — all sub-conditions must agree
        assert_eq!(
            cond.matches(200, "error"),
            ResponseConditionResult::NotChecked
        );
    }

    #[test]
    fn test_condition_raw_body_matches_status_does_not_returns_not_checked() {
        let cond = valid_condition_with_status_and_raw_body(
            StatusCodeMatcher::Single(200),
            BodyMatcher::ExactMatch("ok".to_string()),
        );
        // body matches but status does not — all sub-conditions must agree
        assert_eq!(cond.matches(401, "ok"), ResponseConditionResult::NotChecked);
    }

    #[test]
    fn test_condition_status_and_raw_body_neither_matches_returns_not_checked() {
        let cond = valid_condition_with_status_and_raw_body(
            StatusCodeMatcher::Single(200),
            BodyMatcher::ExactMatch("ok".to_string()),
        );
        assert_eq!(
            cond.matches(401, "error"),
            ResponseConditionResult::NotChecked
        );
    }

    #[test]
    fn test_condition_invalid_type_status_and_raw_body_both_match_returns_invalid() {
        let cond = ResponseCondition {
            condition_type: ResponseConditionType::Invalid,
            status_code: Some(StatusCodeMatcher::Single(401)),
            raw_body: Some(BodyMatcher::ExactMatch("unauthorized".to_string())),
            body: None,
        };
        assert_eq!(
            cond.matches(401, "unauthorized"),
            ResponseConditionResult::Invalid
        );
    }

    #[test]
    fn test_condition_invalid_type_status_matches_raw_body_does_not_returns_not_checked() {
        let cond = ResponseCondition {
            condition_type: ResponseConditionType::Invalid,
            status_code: Some(StatusCodeMatcher::Single(401)),
            raw_body: Some(BodyMatcher::ExactMatch("unauthorized".to_string())),
            body: None,
        };
        // status matches but body does not — the Invalid condition should not fire
        assert_eq!(
            cond.matches(401, "some other body"),
            ResponseConditionResult::NotChecked
        );
    }

    // status_code + body (BTreeMap) combinations

    #[test]
    fn test_condition_status_and_body_map_both_match_returns_valid() {
        let mut body_map = BTreeMap::new();
        body_map.insert(
            "status".to_string(),
            BodyMatcher::ExactMatch("active".to_string()),
        );
        let cond = ResponseCondition {
            condition_type: ResponseConditionType::Valid,
            status_code: Some(StatusCodeMatcher::Single(200)),
            raw_body: None,
            body: Some(body_map),
        };
        assert_eq!(
            cond.matches(200, r#"{"status":"active"}"#),
            ResponseConditionResult::Valid
        );
    }

    #[test]
    fn test_condition_status_matches_body_map_does_not_returns_not_checked() {
        let mut body_map = BTreeMap::new();
        body_map.insert(
            "status".to_string(),
            BodyMatcher::ExactMatch("active".to_string()),
        );
        let cond = ResponseCondition {
            condition_type: ResponseConditionType::Valid,
            status_code: Some(StatusCodeMatcher::Single(200)),
            raw_body: None,
            body: Some(body_map),
        };
        // status matches but the body field does not — condition should not fire
        assert_eq!(
            cond.matches(200, r#"{"status":"inactive"}"#),
            ResponseConditionResult::NotChecked
        );
    }

    #[test]
    fn test_condition_body_map_matches_status_does_not_returns_not_checked() {
        let mut body_map = BTreeMap::new();
        body_map.insert(
            "status".to_string(),
            BodyMatcher::ExactMatch("active".to_string()),
        );
        let cond = ResponseCondition {
            condition_type: ResponseConditionType::Valid,
            status_code: Some(StatusCodeMatcher::Single(200)),
            raw_body: None,
            body: Some(body_map),
        };
        // body field matches but status does not — condition should not fire
        assert_eq!(
            cond.matches(401, r#"{"status":"active"}"#),
            ResponseConditionResult::NotChecked
        );
    }

    #[test]
    fn test_custom_http_v2_config_with_provides() {
        let config: CustomHttpConfigV2 = serde_yaml::from_str(
            r#"
provides:
  - kind: "vendor_xyz"
    name: "client_subdomain"
calls:
  - request:
      endpoint: "https://example.com/validate?secret=$MATCH"
      method: GET
    response:
      conditions: []
"#,
        )
        .unwrap();

        assert_eq!(config.provides.as_ref().map(Vec::len), Some(1));
        let provided = &config.provides.as_ref().unwrap()[0];
        assert_eq!(provided.kind, "vendor_xyz");
        assert_eq!(provided.name, "client_subdomain");
    }

    fn make_exact_body_matcher(path: &str, value: &str) -> BTreeMap<String, BodyMatcher> {
        BTreeMap::from([(path.to_string(), BodyMatcher::ExactMatch(value.to_string()))])
    }

    #[test]
    fn test_get_json_path_value_with_root_prefix() {
        let body: serde_json::Value =
            serde_json::from_str(r#"{"a":{"b":[{"c":"value"}]}}"#).unwrap();

        assert_eq!(
            get_json_path_value(&body, "$.a.b[0].c"),
            Some(&serde_json::Value::String("value".to_string()))
        );
    }

    #[test]
    fn test_get_json_path_value_without_root_prefix() {
        let body: serde_json::Value =
            serde_json::from_str(r#"{"a":{"b":[{"c":"value"}]}}"#).unwrap();

        assert_eq!(
            get_json_path_value(&body, "a.b[0].c"),
            Some(&serde_json::Value::String("value".to_string()))
        );
    }

    #[test]
    fn test_get_json_path_value_with_quoted_numeric_key() {
        let body: serde_json::Value =
            serde_json::from_str(r#"{"a":{"b":{"0":{"c":"value"}}}}"#).unwrap();

        assert_eq!(
            get_json_path_value(&body, "$.a.b['0'].c"),
            Some(&serde_json::Value::String("value".to_string()))
        );
        assert_eq!(
            get_json_path_value(&body, "$.a.b.0.c"),
            Some(&serde_json::Value::String("value".to_string()))
        );
    }

    #[test]
    fn test_get_json_path_value_returns_root_for_dollar() {
        let body: serde_json::Value = serde_json::from_str(r#"{"a":1}"#).unwrap();

        assert_eq!(get_json_path_value(&body, "$"), Some(&body));
    }

    #[test]
    fn test_get_json_path_value_with_root_array() {
        let body: serde_json::Value =
            serde_json::from_str(r#"[{"name":"first"},{"name":"second"}]"#).unwrap();

        assert_eq!(
            get_json_path_value(&body, "$[1].name"),
            Some(&serde_json::Value::String("second".to_string()))
        );
    }

    #[test]
    fn test_get_json_path_value_with_nested_arrays() {
        let body: serde_json::Value =
            serde_json::from_str(r#"{"a":[{"b":[{"c":"value"}]}]}"#).unwrap();

        assert_eq!(
            get_json_path_value(&body, "$.a[0].b[0].c"),
            Some(&serde_json::Value::String("value".to_string()))
        );
    }

    #[test]
    fn test_get_json_path_value_returns_none_for_missing_path() {
        let body: serde_json::Value =
            serde_json::from_str(r#"{"a":{"b":[{"c":"value"}]}}"#).unwrap();

        assert_eq!(get_json_path_value(&body, "$.a.b[1].c"), None);
    }

    #[test]
    fn test_get_json_path_value_returns_none_for_invalid_quoted_key() {
        let body: serde_json::Value =
            serde_json::from_str(r#"{"a":{"b":{"0":{"c":"value"}}}}"#).unwrap();

        assert_eq!(get_json_path_value(&body, "$.a.b[0.c"), None);
    }

    // JSONPath $.a.b[0].c selects the first element from array b.
    #[test]
    fn test_matches_body_jsonpath_array_index() {
        let body = r#"{"a":{"b":[{"c":"value"}]}}"#;
        assert!(matches_body(
            &make_exact_body_matcher("$.a.b[0].c", "value"),
            body
        ));
    }

    // JSONPath $.a.b['0'].c makes object-key access explicit when the key is numeric.
    #[test]
    fn test_matches_body_jsonpath_quoted_numeric_key() {
        let body = r#"{"a":{"b":{"0":{"c":"value"}}}}"#;
        assert!(matches_body(
            &make_exact_body_matcher("$.a.b['0'].c", "value"),
            body
        ));
    }

    #[test]
    fn test_matches_body_jsonpath_without_root_prefix() {
        let body = r#"{"a":{"b":[{"c":"value"}]}}"#;
        assert!(matches_body(
            &make_exact_body_matcher("a.b[0].c", "value"),
            body
        ));
    }
}
