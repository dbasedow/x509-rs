use super::super::error::EncodingError;
use super::{DataType, ToDer};

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
