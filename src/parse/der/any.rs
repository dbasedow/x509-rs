use super::super::error::ParseError;
use super::get_tlv;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AnyRef<'a> {
    tag: u8,
    data: &'a [u8],
}

pub fn take_any(data: &[u8]) -> Result<(&[u8], AnyRef), ParseError> {
    let (rest, tag, data) = get_tlv(data)?;
    Ok((rest, AnyRef { tag, data }))
}
