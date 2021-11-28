use std::convert::TryFrom;
use std::fmt;

use super::super::error::ParseError;
use super::{get_tlv, DataType, ObjectIdentifierRef, PrintableStringRef};

#[derive(PartialEq, Eq, Hash)]
pub struct AnyRef<'a> {
    tag: u8,
    data: &'a [u8],
}

// TODO parse properly
pub fn take_any(data: &[u8]) -> Result<(&[u8], AnyRef), ParseError> {
    let (rest, tag, data) = get_tlv(data)?;
    Ok((rest, AnyRef { tag, data }))
}

impl<'a> fmt::Debug for AnyRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag {
            0x05 => write!(f, "NULL")?,
            0x06 => f
                .debug_tuple("AnyRef")
                .field(&self.to_object_identifier().unwrap())
                .finish()?,
            0x13 => f
                .debug_tuple("AnyRef")
                .field(&self.to_printable_string().unwrap())
                .finish()?,
            t => unimplemented!("tag {}", t),
        }
        Ok(())
    }
}

impl<'a> AnyRef<'a> {
    pub fn to_printable_string(&self) -> Result<PrintableStringRef<'a>, ParseError> {
        match DataType::try_from(self.tag)? {
            DataType::PrintableString => Ok(PrintableStringRef::new(self.data)),
            _ => Err(ParseError::UnsupportedTag(self.tag)),
        }
    }

    pub fn to_object_identifier(&self) -> Result<ObjectIdentifierRef<'a>, ParseError> {
        match DataType::try_from(self.tag)? {
            DataType::ObjectIdentifier => Ok(ObjectIdentifierRef(self.data)),
            _ => Err(ParseError::UnsupportedTag(self.tag)),
        }
    }

    pub fn is_null(&self) -> bool {
        self.tag == 0x05
    }
}
