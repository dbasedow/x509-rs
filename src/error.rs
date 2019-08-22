use std::string::FromUtf8Error;
use std::num::ParseIntError;
use std::fmt::{Formatter, Display};
use std::fmt;

#[derive(Debug)]
pub enum Error {
    ParseError,
    X509Error,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Parse error")
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Error {
        Error::ParseError
    }
}

impl From<ParseIntError> for Error {
    fn from(_: ParseIntError) -> Self {
        Error::ParseError
    }
}

impl std::error::Error for Error {}
