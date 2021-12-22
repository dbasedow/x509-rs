use super::super::error::EncodingError;
use super::{DataType, ToDer};

#[derive(PartialEq, Clone)]
pub struct Null();

impl ToDer for Null {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(vec![])
    }

    fn get_tag(&self) -> u8 {
        DataType::Null.into()
    }
}
