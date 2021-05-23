use crate::error::ParseError;

use super::{DataType, expect_type};


#[derive(Debug, PartialEq)]
pub struct OctetString<'a>(&'a [u8]);


pub fn expect_octet_string(data: &[u8]) -> Result<(&[u8], OctetString), ParseError> {
    let (rest, value) = expect_type(data, DataType::OctetString)?;

    Ok((rest, OctetString(value)))
}
