use std::fmt::{self, Debug, Display, Formatter};

use crate::error::EncodingError;

use super::{DataType, ToDer};

#[derive(PartialEq)]
pub struct Utf8StringRef<'a>(&'a [u8]);

impl<'a> Display for Utf8StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for Utf8StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

pub struct Utf8String(Vec<u8>);

impl Utf8String {
    pub fn from_str(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl ToDer for Utf8String {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(self.0.clone())
    }

    fn get_tag(&self) -> u8 {
        DataType::Utf8String.into()
    }
}
