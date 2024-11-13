use std::fmt;

use crate::{CompiledRuleDyn, MatchStatus, RuleMatch};
use ahash::AHashMap;
use async_trait::async_trait;
use futures::future::join_all;
use lazy_static::lazy_static;
use rayon::prelude::*;
use reqwest::Client;

use super::{
    config::{AwsConfig, AwsType, MatchValidationType},
    match_validator::MatchValidator,
    validator_utils::{generate_aws_headers_and_body, ReqwestResponseAbstraction},
};

lazy_static! {
    static ref AWS_CLIENT: Client = Client::new();
    static ref AWS_BLOCKING_CLIENT: reqwest::blocking::Client = reqwest::blocking::Client::new();
    // Right now the regex matched the secret key with extra characters, this regex aims to extract the secret key only
    static ref AWS_SECRET_REGEX: regex::Regex =
        regex::Regex::new(r"([A-Za-z0-9\/+]{40})\b").unwrap();
}

pub struct AwsValidator {
    pub config: AwsConfig,
}

impl AwsValidator {
    pub fn new(config: AwsConfig) -> Self {
        AwsValidator { config }
    }
    fn get_match_status_per_pairs_of_matches_idx(
        &self,
        matches: &[RuleMatch],
        scanner_rules: &[Box<dyn CompiledRuleDyn>],
    ) -> AHashMap<(usize, usize), MatchStatus> {
        let mut aws_id_matches_idx = vec![];
        let mut aws_secret_matches_idx = vec![];

        for (idx, m) in matches.iter().enumerate() {
            let rule = &scanner_rules[m.rule_index];
            if let Some(MatchValidationType::Aws(aws_type)) = rule.get_match_validation_type() {
                match aws_type {
                    AwsType::AwsId => {
                        aws_id_matches_idx.push(idx);
                    }
                    AwsType::AwsSecret(_) => {
                        aws_secret_matches_idx.push(idx);
                    }
                    AwsType::AwsSession => {
                        // We don't support session for now
                    }
                }
            }
        }

        let mut match_status_per_pairs_of_matches_idx: AHashMap<(usize, usize), MatchStatus> =
            AHashMap::new();
        for aws_id_match_idx in &aws_id_matches_idx {
            for aws_secret_match_idx in &aws_secret_matches_idx {
                match_status_per_pairs_of_matches_idx.insert(
                    (*aws_id_match_idx, *aws_secret_match_idx),
                    MatchStatus::NotChecked,
                );
            }
        }
        match_status_per_pairs_of_matches_idx
    }
}

fn extract_aws_secret_from_match(match_value: &str) -> String {
    let caps = AWS_SECRET_REGEX.captures(match_value);
    if let Some(caps) = caps {
        return caps[1].to_string();
    }
    "".to_string()
}

fn merge_returned_match_status_with_better_status(
    matches: &mut [RuleMatch],
    match_status_per_pairs_of_matches_idx: &AHashMap<(usize, usize), MatchStatus>,
) {
    // Update the matches with the match_status
    // Order is (from higest to lowest) MatchStatus::Valid, MatchStatus::Invalid, MatchStatus::Error
    // Walk through all result and update the matches only if the new match_status has higher priority
    for ((id_index, secret_index), match_status) in match_status_per_pairs_of_matches_idx {
        {
            matches[*id_index].match_status.merge(match_status.clone());
            matches[*secret_index]
                .match_status
                .merge(match_status.clone());
        }
    }
}

fn handle_reqwest_response(match_status: &mut MatchStatus, val: ReqwestResponseAbstraction) {
    // If status is 200-299, then it's valid we can safely update the match status
    // and return
    if val.status().is_success() {
        *match_status = MatchStatus::Valid;
        return;
    }

    if val.status().is_client_error() {
        *match_status = MatchStatus::Invalid;
        return;
    }

    // There might be an issue with the request. We will mark the match_status as error
    // unless it is already valid
    if val.status().is_server_error() {
        *match_status = MatchStatus::Error(fmt::format(format_args!(
            "Unexpected HTTP status code {}",
            val.status().as_u16()
        )));
    }
}

#[async_trait]
impl MatchValidator for AwsValidator {
    fn blocking_validate(
        &self,
        matches: &mut Vec<RuleMatch>,
        scanner_rules: &[Box<dyn CompiledRuleDyn>],
    ) {
        // Let's regroup matches per type
        let mut match_status_per_pairs_of_matches_idx: AHashMap<(usize, usize), MatchStatus> =
            self.get_match_status_per_pairs_of_matches_idx(matches, scanner_rules);

        // Let's try all combination of aws_id and aws_secret
        match_status_per_pairs_of_matches_idx
            .par_iter_mut()
            .for_each(|((id_index, secret_index), match_status)| {
                let match_id = &matches[*id_index].match_value;
                let match_secret = &matches[*secret_index].match_value;
                if match_secret.is_none() {
                    *match_status =
                        MatchStatus::Error("Missing match value for aws_secret".to_string());
                    return;
                }
                if match_id.is_none() {
                    *match_status =
                        MatchStatus::Error("Missing match value for aws_id".to_string());
                    return;
                }
                let match_secret = extract_aws_secret_from_match(match_secret.as_ref().unwrap());
                let match_id = match_id.as_ref().unwrap();
                // Let's reqwest the HTTP API endpoint to validate the matches
                let mut datetime = chrono::Utc::now();
                if self.config.forced_datetime_utc.is_some() {
                    datetime = self.config.forced_datetime_utc.unwrap()
                }
                let (body, headers) = generate_aws_headers_and_body(
                    &datetime,
                    &self.config.aws_sts_endpoint,
                    match_id,
                    &match_secret,
                );
                let res = AWS_BLOCKING_CLIENT
                    .post(self.config.aws_sts_endpoint.as_str())
                    .headers(headers)
                    .body(body)
                    .timeout(self.config.timeout)
                    .send();

                let res = match res {
                    Ok(val) => ReqwestResponseAbstraction::from_sync(val),
                    Err(err) => {
                        *match_status = MatchStatus::Error(fmt::format(format_args!(
                            "Error making HTTP request: {}",
                            err
                        )));
                        return;
                    }
                };
                handle_reqwest_response(match_status, res);
            });

        merge_returned_match_status_with_better_status(
            matches,
            &match_status_per_pairs_of_matches_idx,
        );
    }
    async fn validate(
        &self,
        matches: &mut Vec<RuleMatch>,
        scanner_rules: &[Box<dyn CompiledRuleDyn>],
    ) {
        // Let's regroup matches per type
        let mut match_status_per_pairs_of_matches_idx: AHashMap<(usize, usize), MatchStatus> =
            self.get_match_status_per_pairs_of_matches_idx(matches, scanner_rules);

        // Let's try all combination of aws_id and aws_secret
        let futures = match_status_per_pairs_of_matches_idx.iter_mut().map(
            |((id_index, secret_index), match_status)| {
                let match_id = &matches[*id_index].match_value;
                let match_secret = &matches[*secret_index].match_value;
                async move {
                    if match_secret.is_none() {
                        *match_status =
                            MatchStatus::Error("Missing match value for aws_secret".to_string());
                        return;
                    }
                    if match_id.is_none() {
                        *match_status =
                            MatchStatus::Error("Missing match value for aws_id".to_string());
                        return;
                    }
                    let match_secret =
                        extract_aws_secret_from_match(match_secret.as_ref().unwrap());
                    let match_id = match_id.as_ref().unwrap();
                    // Let's reqwest the HTTP API endpoint to validate the matches
                    let mut datetime = chrono::Utc::now();
                    if self.config.forced_datetime_utc.is_some() {
                        datetime = self.config.forced_datetime_utc.unwrap()
                    }
                    let (body, headers) = generate_aws_headers_and_body(
                        &datetime,
                        &self.config.aws_sts_endpoint,
                        match_id,
                        &match_secret,
                    );
                    let res = AWS_CLIENT
                        .post(self.config.aws_sts_endpoint.as_str())
                        .headers(headers)
                        .body(body)
                        .timeout(self.config.timeout)
                        .send()
                        .await;

                    let res = match res {
                        Ok(val) => ReqwestResponseAbstraction::from_async(val),
                        Err(err) => {
                            *match_status = MatchStatus::Error(fmt::format(format_args!(
                                "Error making HTTP request: {}",
                                err
                            )));
                            return;
                        }
                    };
                    handle_reqwest_response(match_status, res);
                }
            },
        );
        // Wait for all result to complete
        let _ = join_all(futures).await;

        merge_returned_match_status_with_better_status(
            matches,
            &match_status_per_pairs_of_matches_idx,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_aws_secret_from_match() {
        assert_eq!(
            extract_aws_secret_from_match(
                "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(
            extract_aws_secret_from_match(
                "aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(
            extract_aws_secret_from_match("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
    }
}
