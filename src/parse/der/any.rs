use super::super::error::ParseError;
use super::{
    expect_sequence, get_tlv, DataType, IntegerRef, ObjectIdentifierRef, PrintableStringRef,
};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum AnyRef<'a> {
    ObjectIdentifier(ObjectIdentifierRef<'a>),
    Null,
    Integer(IntegerRef<'a>),
    PrintableString(PrintableStringRef<'a>),
    Sequence(&'a [u8]),
}

// TODO parse properly
pub fn take_any(data: &[u8]) -> Result<(&[u8], AnyRef), ParseError> {
    let (rest, tag, data) = get_tlv(data)?;
    match DataType::try_from(tag)? {
        DataType::Null => Ok((rest, AnyRef::Null)),
        DataType::Integer => Ok((rest, AnyRef::Integer(IntegerRef(data)))),
        DataType::ObjectIdentifier => {
            Ok((rest, AnyRef::ObjectIdentifier(ObjectIdentifierRef(data))))
        }
        DataType::PrintableString => {
            Ok((rest, AnyRef::PrintableString(PrintableStringRef::new(data))))
        }
        DataType::Sequence => Ok((rest, AnyRef::Sequence(data))),

        _ => Err(ParseError::UnsupportedTag(tag)),
    }
}
