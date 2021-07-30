use crate::error::{EncodingError, ParseError};

use super::{DataType, ToDer, expect_type};


#[derive(Debug, PartialEq)]
pub struct OctetStringRef<'a>(&'a [u8]);


pub fn expect_octet_string(data: &[u8]) -> Result<(&[u8], OctetStringRef), ParseError> {
    let (rest, value) = expect_type(data, DataType::OctetString)?;

    Ok((rest, OctetStringRef(value)))
}

pub struct OctetString(Vec<u8>);

impl ToDer for OctetString {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(self.0.clone())
    }

    fn get_tag(&self) -> u8 {
        DataType::OctetString.into()
    }
}