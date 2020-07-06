use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use crate::parser::{Parse, ParseError};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Domain(String);

impl Domain {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Domain {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Domain, ParseError> {
        if s.is_empty() {
            return Err(ParseError(format!("invalid domain: {}", s)));
        }
        Ok(Domain(s.to_owned()))
    }
}

impl TryFrom<String> for Domain {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Domain, ParseError> {
        s.parse()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Parse for Domain {
    fn parse(s: &str) -> Result<Domain, ParseError> {
        s.parse()
    }
}
