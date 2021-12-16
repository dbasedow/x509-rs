use super::super::error::EncodingError;
use super::{DataType, ToDer};
use std::convert::TryFrom;

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
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(self.0.clone())
    }

    fn get_tag(&self) -> u8 {
        DataType::IA5String.into()
    }
}
