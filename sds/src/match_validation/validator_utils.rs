use crate::AwsType;

use super::{
    aws_validator::AwsValidator, config::MatchValidationType, http_validator::HttpValidator,
    match_validator::MatchValidator,
};

pub fn new_match_validator_from_type(config: &MatchValidationType) -> Box<dyn MatchValidator> {
    match config {
        MatchValidationType::Aws(aws_config) => match aws_config {
            AwsType::AwsSecret(_) => Box::new(AwsValidator::new()),
            _ => panic!("This aws type shall not be used to create a validator"),
        },
        MatchValidationType::CustomHttp(http_config) => {
            Box::new(HttpValidator::new(http_config.clone()))
        }
    }
}
