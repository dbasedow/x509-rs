use crate::error::ParseError;

use super::get_tlv;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Any<'a> {
    tag: u8,
    data: &'a [u8],
}

pub fn take_any(data: &[u8]) -> Result<(&[u8], Any), ParseError> {
    let (rest, tag, data) = get_tlv(data)?;
    Ok((rest, Any { tag, data }))
}
