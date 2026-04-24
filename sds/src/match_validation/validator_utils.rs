use base64::Engine;
use chrono::{DateTime, Utc};

pub const BASIC_AUTH_ENCODE_SUFFIX: &str = "%basicAuthEncode";

/// If `header_value` matches `Basic <credentials>` , base64-encode the credentials portion.
/// Returns the transformed value, or the original if the pattern doesn't match.
pub fn apply_basic_auth_encode(header_value: &str) -> String {
    let Some(credentials) = header_value.strip_prefix("Basic ") else {
        return header_value.to_string();
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
    format!("Basic {encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_auth_encode_standard_credentials() {
        assert_eq!(
            apply_basic_auth_encode("Basic user:password"),
            "Basic dXNlcjpwYXNzd29yZA=="
        );
    }

    #[test]
    fn test_basic_auth_encode_empty_username() {
        assert_eq!(
            apply_basic_auth_encode("Basic :password"),
            "Basic OnBhc3N3b3Jk"
        );
    }

    #[test]
    fn test_basic_auth_encode_no_colon() {
        assert_eq!(
            apply_basic_auth_encode("Basic tokenonly"),
            "Basic dG9rZW5vbmx5"
        );
    }

    #[test]
    fn test_basic_auth_encode_non_basic_prefix_is_noop() {
        assert_eq!(
            apply_basic_auth_encode("Bearer user:password"),
            "Bearer user:password"
        );
    }

    #[test]
    fn test_basic_auth_encode_empty_string_is_noop() {
        assert_eq!(apply_basic_auth_encode(""), "");
    }

    #[test]
    fn test_basic_auth_encode_multiple_colons() {
        assert_eq!(
            apply_basic_auth_encode("Basic user:pass:extra"),
            "Basic dXNlcjpwYXNzOmV4dHJh"
        );
    }
}

pub fn generate_aws_headers_and_body(
    datetime: &DateTime<Utc>,
    endpoint: &str,
    aws_id: &str,
    aws_secret: &str,
) -> (String, reqwest::header::HeaderMap) {
    let mut headers = reqwest::header::HeaderMap::new();
    let datetime_str = datetime.format("%Y%m%dT%H%M%SZ").to_string();
    headers.insert("X-Amz-Date", datetime_str.parse().unwrap());
    headers.insert("Accept-Encoding", "identity".parse().unwrap());
    headers.insert(
        "Content-Type",
        "application/x-www-form-urlencoded; charset=utf-8"
            .parse()
            .unwrap(),
    );
    headers.insert("host", "sts.us-east-1.amazonaws.com".parse().unwrap());

    let body = "Action=GetCallerIdentity&Version=2011-06-15".to_string();
    let s = aws_sign_v4::AwsSign::new(
        "POST",
        endpoint,
        datetime,
        &headers,
        "us-east-1", // default region
        aws_id,
        aws_secret,
        "sts",
        body.as_str(),
    );
    let signature = s.sign();
    headers.insert(reqwest::header::AUTHORIZATION, signature.parse().unwrap());

    (body, headers)
}
