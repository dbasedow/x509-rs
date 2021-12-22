use super::super::error::EncodingError;
use super::{DataType, ToDer};

#[derive(Debug, PartialEq)]
pub struct OctetStringRef<'a>(&'a [u8]);

#[derive(Clone)]
pub struct OctetString(Vec<u8>);

impl OctetString {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl ToDer for OctetString {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(self.0.clone())
    }

    fn get_tag(&self) -> u8 {
        DataType::OctetString.into()
    }
}
