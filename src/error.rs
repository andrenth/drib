use std::fmt;

use tokio::io;

use super::parser::ParseError;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ParseNet(ParseError),
    ParseConfig(serde_yaml::Error),
    Config(ConfigError),
    Render(tera::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {}", e),
            Error::ParseNet(e) => write!(f, "parse network error: {}", e),
            Error::ParseConfig(e) => write!(f, "configuration error: {}", e),
            Error::Config(e) => write!(f, "configuration error: {}", e),
            Error::Render(e) => write!(f, "render error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::ParseNet(e) => Some(e),
            Error::ParseConfig(e) => Some(e),
            Error::Config(e) => Some(e),
            Error::Render(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Error {
        Error::ParseNet(e)
    }
}

impl From<tera::Error> for Error {
    fn from(e: tera::Error) -> Error {
        Error::Render(e)
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Error {
        Error::ParseConfig(e)
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Error {
        Error::Config(e)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    MissingSetting(String),
    ClassIntersection(ClassIntersectionError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ConfigError::MissingSetting(name) => write!(f, "{} is missing", name),
            ConfigError::ClassIntersection(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::MissingSetting(_) => None,
            ConfigError::ClassIntersection(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct ClassIntersectionError {
    pub classes: (String, String),
    pub intersection: Vec<String>,
}

impl fmt::Display for ClassIntersectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "classes {} and {} contain intersecting ranges: {}",
            self.classes.0,
            self.classes.1,
            self.intersection.join(", ")
        )
    }
}

impl std::error::Error for ClassIntersectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
