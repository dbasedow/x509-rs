use super::super::error::ParseError;
use super::{
    get_tlv, DataType, IntegerRef, ObjectIdentifierRef, PrintableStringRef, Utf8StringRef,
};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum AnyRef<'a> {
    ObjectIdentifier(ObjectIdentifierRef<'a>),
    Null,
    Integer(IntegerRef<'a>),
    PrintableString(PrintableStringRef<'a>),
    Utf8String(Utf8StringRef<'a>),
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
        DataType::PrintableString => Ok((rest, AnyRef::PrintableString(PrintableStringRef(data)))),
        DataType::Utf8String => Ok((rest, AnyRef::Utf8String(Utf8StringRef(data)))),
        DataType::Sequence => Ok((rest, AnyRef::Sequence(data))),

        _ => Err(ParseError::UnsupportedTag(tag)),
    }
}
