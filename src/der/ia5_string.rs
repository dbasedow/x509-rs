use crate::error::{EncodingError, Error, ParseError};
use std::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
};

use super::{DataType, ToDer};

#[derive(PartialEq)]
pub struct IA5StringRef<'a>(&'a [u8]);

impl<'a> IA5StringRef<'a> {
    pub fn to_string(&self) -> Result<String, Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            return Ok(s);
        }
        Err(Error::ParseError(ParseError::StringEncoding))
    }
}

impl<'a> Display for IA5StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for IA5StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

pub struct IA5String(Vec<u8>);

impl TryFrom<&str> for IA5String {
    type Error = EncodingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.is_ascii() {
            return Err(EncodingError::StringNotAscii);
        }

        Ok(Self(value.as_bytes().to_vec()))
    }
}

impl ToDer for IA5String {
    fn to_der(&self) -> Vec<u8> {
        super::encode_tlv(DataType::IA5String.into(), &self.0)
    }
}
