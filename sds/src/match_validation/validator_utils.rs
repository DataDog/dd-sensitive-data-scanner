use chrono::{DateTime, Utc};

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
