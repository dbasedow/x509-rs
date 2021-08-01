use crate::error::ParseError;
use std::fmt::{self, Debug, Formatter};

use super::{expect_type, DataType, ToDer};

#[derive(PartialEq)]
pub struct Boolean(u8);

impl Boolean {
    pub fn to_bool(&self) -> bool {
        self.0 == 0xff
    }
}

impl Debug for Boolean {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let b = self.to_bool();
        write!(f, "{:#?}", b)
    }
}

pub fn expect_boolean(data: &[u8]) -> Result<(&[u8], Boolean), ParseError> {
    let (rest, value) = expect_type(data, DataType::Boolean)?;
    if value.len() != 1 {
        return Err(ParseError::InvalidLength);
    }

    Ok((rest, Boolean(value[0])))
}

impl ToDer for Boolean {
    fn encode_inner(&self) -> Result<Vec<u8>, crate::error::EncodingError> {
        Ok(vec![self.0; 1])
    }

    fn get_tag(&self) -> u8 {
        DataType::Boolean.into()
    }
}

impl From<Boolean> for bool {
    fn from(v: Boolean) -> Self {
        v.to_bool()
    }
}

impl From<bool> for Boolean {
    fn from(b: bool) -> Self {
        if b {
            Boolean(0xff)
        } else {
            Boolean(0x00)
        }
    }
}
