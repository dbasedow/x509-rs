use super::super::error::EncodingError;
use super::{DataType, ToDer};
use std::fmt::{self, Debug, Formatter};

#[derive(PartialEq, Clone)]
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

impl ToDer for Boolean {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
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
