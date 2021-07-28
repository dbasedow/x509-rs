use std::fmt::{self, Debug, Display, Formatter};

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
    fn to_der(&self) -> Vec<u8> {
        super::encode_tlv(DataType::Utf8String.into(), &self.0)
    }
}
