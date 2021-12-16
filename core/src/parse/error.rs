use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
    ParseError(ParseError),
    EncodingError(EncodingError),
    X509Error,
    IndexOutOfBoundsError,
    InvalidSignature,
}

#[derive(Debug)]
pub enum ParseError {
    UnsupportedTag(u8),
    MalformedData,
    InvalidLength,
    StringEncoding,
    UnexpectedTag(u8),
    InvalidVersion,
}

#[derive(Debug)]
pub enum EncodingError {
    StringNotAscii,
    MissingRequiredField(&'static str),
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
