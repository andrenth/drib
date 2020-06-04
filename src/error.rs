use std::fmt;

use tokio::io;

use super::parser::ParseError;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Parse(ParseError),
    Render(tinytemplate::error::Error),
    Config(serde_yaml::Error),
    Class(ClassError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {}", e),
            Error::Parse(e) => write!(f, "parse error: {}", e),
            Error::Render(e) => write!(f, "render error: {}", e),
            Error::Config(e) => write!(f, "configuration error: {}", e),
            Error::Class(e) => write!(f, "configuration error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Parse(e) => Some(e),
            Error::Render(e) => Some(e),
            Error::Config(e) => Some(e),
            Error::Class(e) => Some(e),
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
        Error::Parse(e)
    }
}

impl From<tinytemplate::error::Error> for Error {
    fn from(e: tinytemplate::error::Error) -> Error {
        Error::Render(e)
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Error {
        Error::Config(e)
    }
}

impl From<ClassError> for Error {
    fn from(e: ClassError) -> Error {
        Error::Class(e)
    }
}

#[derive(Debug)]
pub struct ClassError {
    pub classes: (String, String),
    pub intersection: Vec<String>,
}

impl fmt::Display for ClassError {
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

impl std::error::Error for ClassError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
