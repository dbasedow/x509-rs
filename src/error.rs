use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    ParseError(crate::parse::error::ParseError),
    EncodingError(crate::generate::error::EncodingError),
    X509Error,
    IndexOutOfBoundsError,
    InvalidSignature,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Parse error")
    }
}

impl std::error::Error for Error {}
