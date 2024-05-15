use crate::parser::input::Input;
use nom::error::{Error, ErrorKind};

/// The parser gives very limited information currently on errors. It's either "invalid" or
/// it exceeded the depth limit.
#[derive(Clone, Debug, PartialEq)]
pub enum ParseError {
    InvalidSyntax,
    ExceededDepthLimit,
    ExceededQuantifierLimit,
}

impl<'a> nom::error::ParseError<Input<'a>> for ParseError {
    fn from_error_kind(input: Input<'a>, kind: ErrorKind) -> Self {
        ParseError::from(Error::new(input, kind))
    }

    fn append(_input: Input<'a>, _kind: ErrorKind, other: Self) -> Self {
        // the input/kind can only ever be a syntax error. A depth limit overrides syntax,
        // so input/kind can be completely ignored
        other
    }
}

impl<'a> From<Error<Input<'a>>> for ParseError {
    fn from(_value: Error<Input<'a>>) -> Self {
        // any error that nom internally generates (ErrorKind) will always be a syntax error
        Self::InvalidSyntax
    }
}
