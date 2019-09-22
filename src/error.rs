use std::string::FromUtf8Error;
use std::num::ParseIntError;
use std::fmt::{Formatter, Display};
use std::fmt;

#[derive(Debug)]
pub enum Error {
    ParseError(ParseError),
    X509Error,
    IndexOutOfBoundsError,
}

#[derive(Debug)]
pub enum ParseError {
    UnsupportedTag(u8),
    MalformedData,
    InvalidLength,
    StringEncoding,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Parse error")
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Error {
        Error::ParseError(ParseError::StringEncoding)
    }
}

impl From<ParseIntError> for Error {
    fn from(_: ParseIntError) -> Self {
        Error::ParseError(ParseError::MalformedData)
    }
}

impl std::error::Error for Error {}
