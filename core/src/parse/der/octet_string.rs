use super::super::error::ParseError;
use super::{expect_type, DataType};

#[derive(Debug, PartialEq)]
pub struct OctetStringRef<'a>(&'a [u8]);

pub fn expect_octet_string(data: &[u8]) -> Result<(&[u8], OctetStringRef), ParseError> {
    let (rest, value) = expect_type(data, DataType::OctetString)?;

    Ok((rest, OctetStringRef(value)))
}
