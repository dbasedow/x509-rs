use crate::error::{Error, ParseError};
use std::convert::TryFrom;

pub(crate) fn ascii_to_digit(d: u8) -> Result<u32, Error> {
    if d >= 0x30 && d <= 0x39 {
        Ok((d & 0x0f) as u32)
    } else {
        Err(Error::ParseError(ParseError::MalformedData))
    }
}

pub(crate) fn ascii_slice_to_u32(data: &[u8]) -> Result<u32, Error> {
    let mut res: u32 = 0;
    for &ch in data {
        res = res * 10 + ascii_to_digit(ch)?;
    }

    Ok(res)
}

#[derive(Eq, PartialEq)]
pub enum DataType {
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifier,
    Utf8String,
    Sequence,
    Set,
    PrintableString,
    T61String,
    IA5String,
    UTCTime,
    GeneralizedTime,
    VisibleString,
    BMPString,
}

impl TryFrom<u8> for DataType {
    type Error = ParseError;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        if tag & 0xc0 != 0x00 {
            // this is not a universal type!!!
            return Err(ParseError::UnexpectedTag(tag));
        }

        let constructed = tag & 0x20 == 0x20;
        let tag = tag & 0x1f;
        match (tag, constructed) {
            (0x01, false) => Ok(DataType::Boolean),
            (0x02, false) => Ok(DataType::Integer),
            (0x03, _) => Ok(DataType::BitString),
            (0x04, _) => Ok(DataType::OctetString),
            (0x05, false) => Ok(DataType::Null),
            (0x06, false) => Ok(DataType::ObjectIdentifier),
            (0x0c, _) => Ok(DataType::Utf8String),
            (0x10, true) => Ok(DataType::Sequence),
            (0x11, true) => Ok(DataType::Set),
            (0x13, _) => Ok(DataType::PrintableString),
            (0x14, _) => Ok(DataType::T61String),
            (0x16, _) => Ok(DataType::IA5String),
            (0x17, _) => Ok(DataType::UTCTime),
            (0x18, _) => Ok(DataType::GeneralizedTime),
            (0x1a, _) => Ok(DataType::VisibleString),
            (0x1e, _) => Ok(DataType::BMPString),

            (t, _) => Err(ParseError::UnsupportedTag(t)),
        }
    }
}

impl From<DataType> for u8 {
    fn from(t: DataType) -> Self {
        match t {
            DataType::Boolean => 0x01,
            DataType::Integer => 0x02,
            DataType::BitString => 0x03,
            DataType::OctetString => 0x04,
            DataType::Null => 0x05,
            DataType::ObjectIdentifier => 0x06,
            DataType::Utf8String => 0x0c,
            DataType::Sequence => 0x10,
            DataType::Set => 0x11,
            DataType::PrintableString => 0x13,
            DataType::T61String => 0x14,
            DataType::IA5String => 0x16,
            DataType::UTCTime => 0x17,
            DataType::GeneralizedTime => 0x18,
            DataType::VisibleString => 0x1a,
            DataType::BMPString => 0x1e,
        }
    }
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();
    res.push(tag);

    let len = value.len();
    if len <= 127 {
        // short encoding
        res.push(len as u8);
    } else {
        // long encoding
        let length_bytes = len.to_be_bytes();
        let pos = length_bytes.iter().position(|b| *b != 0x00).unwrap(); // we can unwrap, since len > 127
        let length_bytes_no_prefix = &length_bytes[pos..];
        let length_length = length_bytes_no_prefix.len() as u8; // length of length is guaranteed to be <= 8 on 64bit systems
        res.push(length_length);
        res.extend_from_slice(length_bytes_no_prefix);
    }
    res.extend_from_slice(value);

    res
}

/// returns (rest, tag, value)
fn get_tlv(data: &[u8]) -> Result<(&[u8], u8, &[u8]), ParseError> {
    if data.len() < 2 {
        // we need at least a tag and a length (which may be 0)
        return Err(ParseError::MalformedData);
    }

    let mut consumed: usize = 0;

    // we only handle single byte tags
    let tag = data[0];
    consumed += 1;

    let first_length_octet = data[consumed];
    consumed += 1;

    let long_length_encoding = first_length_octet & 0x80 == 0x80;

    let length;
    if long_length_encoding {
        let length_length = (first_length_octet & 0x7f) as usize;
        if length_length > 8 {
            return Err(ParseError::InvalidLength);
        }
        if length_length + 2 > data.len() {
            return Err(ParseError::InvalidLength);
        }
        let mut tmp_length: usize = 0;
        for &octet in &data[2..2 + length_length] {
            consumed += 1;
            tmp_length = tmp_length << 8;
            tmp_length += octet as usize;
        }
        length = tmp_length;
    } else {
        length = (first_length_octet & 0x7f) as usize;
    }

    if length + consumed > data.len() {
        return Err(ParseError::InvalidLength);
    }

    Ok((
        &data[consumed + length..],
        tag,
        &data[consumed..consumed + length],
    ))
}

pub fn expect_type(data: &[u8], expected: DataType) -> Result<(&[u8], &[u8]), ParseError> {
    let (rest, tag, inner_data) = get_tlv(data)?;
    let typ = DataType::try_from(tag)?;

    if typ != expected {
        return Err(ParseError::UnexpectedTag(tag));
    }

    Ok((rest, inner_data))
}

pub fn expect_sequence(data: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    expect_type(data, DataType::Sequence)
}

pub fn expect_set(data: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    expect_type(data, DataType::Set)
}

pub struct ExplicitTag(u8);

impl ExplicitTag {
    pub fn try_new(tag: u8) -> Result<Self, ParseError> {
        // make sure the 3 high bits are not set, those are needed for tag class and P/C flag
        if tag < 0x1f {
            Ok(Self(tag))
        } else {
            Err(ParseError::UnsupportedTag(tag))
        }
    }

    fn get_identifier_octet(&self) -> u8 {
        0xa0 | self.0
    }
}

pub fn try_get_explicit(data: &[u8], expected: ExplicitTag) -> Result<(&[u8], &[u8]), ParseError> {
    let (rest, tag, inner_data) = get_tlv(data)?;
    if tag & 0xe0 != 0xa0 {
        // this tag is not an explicit tag
        return Err(ParseError::UnexpectedTag(tag));
    }

    if tag & 0x1f != expected.0 {
        return Err(ParseError::UnexpectedTag(tag));
    }

    Ok((rest, inner_data))
}

pub fn wrap_in_explicit_tag(inner: &[u8], tag: ExplicitTag) -> Vec<u8> {
    encode_tlv(tag.get_identifier_octet(), inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_get_tlv() {
        let d = hex::decode("06062a864886f70d").unwrap();
        let res = get_tlv(&d);
        assert!(res.is_ok());
        let (rest, tag, value) = res.ok().unwrap();
        assert!(rest.is_empty());
        assert_eq!(tag, 0x06);
        assert_eq!(hex::encode(value), "2a864886f70d");
    }

    #[test]
    fn test_encode_tlv() {
        let tlv = encode_tlv(0x02, &[0x01]);
        let res = get_tlv(&tlv);
        assert!(res.is_ok());
        let (rest, tag, value) = res.ok().unwrap();
        assert!(rest.is_empty());
        assert_eq!(tag, 0x02);
        assert_eq!(value, &[0x01]);
    }

    #[test]
    fn test_try_get_explicit() {
        let d = hex::decode("A003020102").unwrap();
        let r = try_get_explicit(&d, ExplicitTag::try_new(0).unwrap());
        assert!(r.is_ok());
        let (rest, inner) = r.unwrap();
        assert!(rest.is_empty());
        assert_eq!(inner.len(), 3);
    }

    #[test]
    fn test_try_get_explicit_wrong_tag() {
        let d = hex::decode("A103020102").unwrap();
        let r = try_get_explicit(&d, ExplicitTag::try_new(0).unwrap());
        assert!(r.is_err());
    }

    #[test]
    fn test_try_get_explicit_non_explicit_input() {
        let d = hex::decode("1003020102").unwrap();
        let r = try_get_explicit(&d, ExplicitTag::try_new(0).unwrap());
        assert!(r.is_err());
    }

    #[test]
    fn test_expect_sequence() {
        let d = hex::decode("3020170d3134303830313030303030305a180f32303530303930343030303030305a")
            .unwrap();
        let res = expect_sequence(&d);
        assert!(res.is_ok());
        let (rest, _) = res.unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn test_wrap_in_explicit() {
        let res = wrap_in_explicit_tag(&[0x10, 0x10], ExplicitTag::try_new(0x01).unwrap());
        assert_eq!(res, &[0xa1, 0x02, 0x10, 0x10]);
    }
}

pub trait ToDer {
    fn to_der(&self) -> Vec<u8>;
}

pub use any::{take_any, AnyRef};
pub use bit_string::{expect_bit_string, BitStringRef};
pub use bmp_string::BMPStringRef;
pub use boolean::{expect_boolean, Boolean};
pub use generalized_time::{expect_generalized_time, GeneralizedTimeRef};
pub use ia5_string::IA5StringRef;
pub use integer::{expect_integer, IntegerRef, Integer};
pub use object_identifier::{expect_object_identifier, ObjectIdentifier, ObjectIdentifierRef};
pub use octet_string::{expect_octet_string, OctetStringRef};
pub use printable_string::PrintableStringRef;
pub use t61_string::T61StringRef;
pub use utc_time::{expect_utc_time, UTCTimeRef};
pub use utf8_string::Utf8StringRef;
pub use visible_string::VisibleStringRef;

mod any;
mod bit_string;
mod bmp_string;
mod boolean;
mod generalized_time;
mod ia5_string;
mod integer;
mod object_identifier;
mod octet_string;
mod printable_string;
mod t61_string;
mod utc_time;
mod utf8_string;
mod visible_string;
