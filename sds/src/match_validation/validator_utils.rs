use chrono::{DateTime, Utc};

use crate::AwsType;

use super::{
    aws_validator::AwsValidator, config::MatchValidationType, http_validator::HttpValidator,
    match_validator::MatchValidator,
};

pub fn new_match_validator_from_type(config: MatchValidationType) -> Box<dyn MatchValidator> {
    match config {
        MatchValidationType::Aws(aws_config) => match aws_config {
            AwsType::AwsSecret(config) => Box::new(AwsValidator::new(config)),
            _ => panic!("This aws type shall not be used to create a validator"),
        },
        MatchValidationType::CustomHttp(http_config) => Box::new(HttpValidator::new(http_config)),
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
        &datetime,
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
