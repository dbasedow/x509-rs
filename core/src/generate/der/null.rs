use super::super::error::EncodingError;
use super::{DataType, ToDer};

#[derive(PartialEq)]
pub struct Null();

impl ToDer for Null {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(vec![0x00])
    }

    fn get_tag(&self) -> u8 {
        DataType::Null.into()
    }
}
