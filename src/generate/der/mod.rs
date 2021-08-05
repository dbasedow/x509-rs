use crate::common::der::ExplicitTag;

use super::error::EncodingError;
use chrono::prelude::*;

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

impl DataType {
    pub fn constructed(self) -> u8 {
        let tag: u8 = self.into();
        tag | 0x20
    }
}

pub fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
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
        let length_length_flagged = length_length | 0x80;
        res.push(length_length_flagged);
        res.extend_from_slice(length_bytes_no_prefix);
    }
    res.extend_from_slice(value);

    res
}

pub fn wrap_in_explicit_tag(inner: &[u8], tag: ExplicitTag) -> Vec<u8> {
    encode_tlv(tag.get_identifier_octet(), inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_in_explicit() {
        let res = wrap_in_explicit_tag(&[0x10, 0x10], ExplicitTag::try_new(0x01).unwrap());
        assert_eq!(res, &[0xa1, 0x02, 0x10, 0x10]);
    }
}

pub trait ToDer {
    /// encodes the inner value, without the length and tag
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError>;
    /// encodes the whole value
    fn to_der(&self) -> Result<Vec<u8>, EncodingError> {
        let tlv = encode_tlv(self.get_tag(), &self.encode_inner()?);

        Ok(tlv)
    }
    fn get_tag(&self) -> u8;
}

impl ToDer for DateTime<Utc> {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let year = self.year();
        if year >= 1950 && year < 2049 {
            let yy = year % 100;
            let s = format!(
                "{}{}{}{}{}{}Z",
                yy,
                self.month(),
                self.day(),
                self.hour(),
                self.minute(),
                self.second()
            );

            Ok(s.as_bytes().to_vec())
        } else {
            let yy = year % 100;
            let s = format!(
                "{}{}{}{}{}{}Z",
                yy,
                self.month(),
                self.day(),
                self.hour(),
                self.minute(),
                self.second()
            );

            Ok(s.as_bytes().to_vec())
        }
    }

    fn get_tag(&self) -> u8 {
        let year = self.year();
        if year >= 1950 && year < 2049 {
            DataType::UTCTime.into()
        } else {
            DataType::GeneralizedTime.into()
        }
    }
}

pub use bit_string::BitString;
pub use boolean::Boolean;
pub use integer::Integer;
pub use null::Null;
pub use object_identifier::ObjectIdentifier;
pub use octet_string::{OctetString, OctetStringRef};
pub use utf8_string::Utf8String;
pub use visible_string::VisibleStringRef;

mod bit_string;
mod boolean;
mod ia5_string;
mod integer;
mod null;
mod object_identifier;
mod octet_string;
mod utf8_string;
mod visible_string;
