use crate::error::{Error, ParseError};
use chrono::prelude::*;
use std::convert::TryFrom;
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Any<'a> {
    tag: u8,
    data: &'a [u8],
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier(Vec<u8>);

impl ObjectIdentifier {
    pub fn from_str(s: &str) -> Result<Self, ()> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 2 {
            return Err(());
        }

        let x = u8::from_str(parts[0]).map_err(|_| ())?;
        if x > 5 {
            return Err(());
        }

        let y = u8::from_str(parts[1]).map_err(|_| ())?;
        if y > 40 {
            return Err(());
        }

        let xy = x * 40 + y;
        let mut data: Vec<u8> = Vec::new();
        data.push(xy);

        for part in &parts[2..] {
            let part = u64::from_str(part).map_err(|_| ())?;
            if part <= 0x7f {
                data.push(part as u8);
            } else {
                data.extend_from_slice(&encode_oid_part(part));
            }
        }
        Ok(Self(data))
    }
}

fn encode_oid_part(n: u64) -> Vec<u8> {
    let mut res = Vec::new();
    let mut n = n;
    while n > 0 {
        let mut b = (n & 0x7f) as u8;

        // if this is not the lowest byte set bit 8 to 1
        if res.len() > 0 {
            b = b | 0x80;
        }

        res.push(b);
        n = n >> 7;
    }
    res.reverse();
    res
}

impl<'a> From<&'a ObjectIdentifier> for ObjectIdentifierRef<'a> {
    fn from(oid: &'a ObjectIdentifier) -> Self {
        Self(&oid.0)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifierRef<'a>(&'a [u8]);

impl<'a> ObjectIdentifierRef<'a> {
    pub fn to_parts(&self) -> Vec<u64> {
        let mut res = Vec::new();
        let data = self.0;
        let y = data[0] % 40;
        let x = (data[0] - y) / 40;

        res.push(x as u64);
        res.push(y as u64);

        let mut sub_id: u64 = 0;

        for &octet in &data[1..] {
            sub_id = sub_id << 7;
            sub_id += (octet & 0x7f) as u64;

            if octet & 0x80 == 0 {
                //last part of subid.
                res.push(sub_id);
                sub_id = 0;
            }
        }

        res
    }
}

impl<'a> Display for ObjectIdentifierRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        for (index, &sub_id) in self.to_parts().iter().enumerate() {
            if index > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", sub_id)?;
        }
        Ok(())
    }
}

impl<'a> Debug for ObjectIdentifierRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(PartialEq)]
pub struct Boolean(u8);

impl Boolean {
    pub fn to_bool(&self) -> bool {
        self.0 == 0xff
    }
}

impl Debug for Boolean {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let b = self.to_bool();
        write!(f, "{:#?}", b)
    }
}

#[derive(PartialEq)]
pub struct Integer<'a>(&'a [u8]);

impl<'a> Integer<'a> {
    pub fn to_i64(&self) -> Result<i64, ParseError> {
        let data = self.0;
        if data.len() > 8 {
            // can't fit value in i64
            return Err(ParseError::InvalidLength);
        }

        let mut res: i64 = 0;
        let a = data[0] as i8;
        res += a as i64;

        for &octet in &data[1..] {
            res = res << 8;
            res = res | octet as i64;
        }
        Ok(res)
    }

    pub fn to_big_int(&self) -> num_bigint::BigInt {
        num_bigint::BigInt::from_signed_bytes_be(self.0)
    }
}

impl<'a> Debug for Integer<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let i = self.to_i64();
        write!(f, "{:#?}", i)
    }
}

#[derive(PartialEq)]
pub struct PrintableString<'a>(&'a [u8]);

impl<'a> Display for PrintableString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for PrintableString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(PartialEq)]
pub struct T61String<'a>(&'a [u8]);

impl<'a> Display for T61String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", String::from_utf8_lossy(self.0))
    }
}

impl<'a> Debug for T61String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(PartialEq)]
pub struct IA5String<'a>(&'a [u8]);

impl<'a> IA5String<'a> {
    pub fn to_string(&self) -> Result<String, Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            return Ok(s);
        }
        Err(Error::ParseError(ParseError::StringEncoding))
    }
}

impl<'a> Display for IA5String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for IA5String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(PartialEq)]
pub struct Utf8String<'a>(&'a [u8]);

impl<'a> Display for Utf8String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for Utf8String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(PartialEq)]
pub struct VisibleString<'a>(&'a [u8]);

impl<'a> Display for VisibleString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let s = String::from_utf8_lossy(self.0);
        write!(f, "{}", s)
    }
}

impl<'a> Debug for VisibleString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(PartialEq)]
pub struct BMPString<'a>(&'a [u8]);

impl<'a> Display for BMPString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let u16s: Vec<u16> = self
            .0
            .chunks(2)
            .map(|a| u16::from_be_bytes([a[0], a[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&u16s) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for BMPString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(PartialEq)]
pub struct UTCTime<'a>(&'a [u8]);

impl<'a> UTCTime<'a> {
    pub fn to_datetime(&self) -> Result<DateTime<FixedOffset>, Error> {
        let data = self.0;
        let year = ascii_slice_to_u32(&data[..2])?;
        let year = year + 2000;

        let month = ascii_slice_to_u32(&data[2..4])?;
        let day = ascii_slice_to_u32(&data[4..6])?;

        let hour = ascii_slice_to_u32(&data[6..8])?;
        let minute = ascii_slice_to_u32(&data[8..10])?;

        let second;
        if data.len() == 13 || data.len() == 17 {
            second = ascii_slice_to_u32(&data[10..12])?;
        } else {
            second = 0;
        }

        let utc_offset: i32;
        if data.len() == 17 {
            let hour_offset = ascii_slice_to_u32(&data[11..13])?;
            let minute_offset = ascii_slice_to_u32(&data[14..16])?;
            let factor = if data[10] == 0x2d {
                // '-'
                -1
            } else {
                1
            };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        } else if data.len() == 19 {
            let hour_offset = ascii_slice_to_u32(&data[13..15])?;
            let minute_offset = ascii_slice_to_u32(&data[16..18])?;
            let factor = if data[12] == 0x2d {
                // '-'
                -1
            } else {
                1
            };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        } else {
            utc_offset = 0;
        }

        let offset = FixedOffset::east(utc_offset);
        let dt = offset
            .ymd(year as i32, month, day)
            .and_hms(hour, minute, second);

        Ok(dt)
    }
}

fn ascii_to_digit(d: u8) -> Result<u32, Error> {
    if d >= 0x30 && d <= 0x39 {
        Ok((d & 0x0f) as u32)
    } else {
        Err(Error::ParseError(ParseError::MalformedData))
    }
}

fn ascii_slice_to_u32(data: &[u8]) -> Result<u32, Error> {
    let mut res: u32 = 0;
    for &ch in data {
        res = res * 10 + ascii_to_digit(ch)?;
    }

    Ok(res)
}

impl<'a> Display for UTCTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(dt) = self.to_datetime() {
            write!(f, "{}", dt.to_rfc3339())
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for UTCTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(PartialEq)]
pub struct GeneralizedTime<'a>(&'a [u8]);

impl<'a> GeneralizedTime<'a> {
    pub fn to_datetime(&self) -> Result<DateTime<FixedOffset>, Error> {
        let data = self.0;
        let year = ascii_slice_to_u32(&data[..4])?;

        let month = ascii_slice_to_u32(&data[4..6])?;
        let day = ascii_slice_to_u32(&data[6..8])?;

        let hour = ascii_slice_to_u32(&data[8..10])?;
        let minute = ascii_slice_to_u32(&data[10..12])?;
        let second = ascii_slice_to_u32(&data[12..14])?;

        let nanos: u32;
        if data[14] == 0x2e {
            // '.'
            // handle fractional seconds
            let mut fractional_len = 0;
            for (i, &ch) in (&data[15..]).iter().enumerate() {
                if ch > 0x39 || ch < 0x30 {
                    //end of fractional seconds
                    fractional_len = i;
                }
            }
            nanos = ascii_slice_to_u32(&data[15..15 + fractional_len])?;
        } else {
            nanos = 0;
        }

        let utc_offset: i32;
        if data[data.len() - 1] == 0x5a {
            // 'Z'
            utc_offset = 0;
        } else {
            let data = &data[data.len() - 6..];
            let hour_offset = ascii_slice_to_u32(&data[1..3])?;
            let minute_offset = ascii_slice_to_u32(&data[3..5])?;
            let factor = if data[0] == 0x2d {
                // '-'
                -1
            } else {
                1
            };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        }

        let offset = FixedOffset::east(utc_offset);
        let dt = offset
            .ymd(year as i32, month, day)
            .and_hms_nano(hour, minute, second, nanos);

        Ok(dt)
    }
}

impl<'a> Display for GeneralizedTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(dt) = self.to_datetime() {
            write!(f, "{}", dt.to_rfc3339())
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for GeneralizedTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

#[derive(Debug, PartialEq)]
pub struct OctetString<'a>(&'a [u8]);

#[derive(Debug, PartialEq)]
pub struct BitString<'a>(&'a [u8]);

impl<'a> BitString<'a> {
    pub fn bit_at(&self, index: usize) -> Result<bool, Error> {
        // First Byte contains amount of padding in bits
        let len = (self.0.len() - 1) * 8 - self.0[0] as usize;
        if index + 1 > len {
            return Err(Error::IndexOutOfBoundsError);
        }
        // add one to byte offset, since first byte in the bit string is the padding size
        let byte_offset = index / 8 + 1;
        let bit_offset = (index % 8) as u8;

        let mask = 0x80 >> bit_offset;
        let byte = self.0[byte_offset];

        Ok(byte & mask == mask)
    }

    pub fn data(&self) -> (u8, &'a [u8]) {
        (self.0[0], &self.0[1..])
    }
}

#[derive(Eq, PartialEq)]
pub enum DataType {
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifierRef,
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
            (0x06, false) => Ok(DataType::ObjectIdentifierRef),
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

pub fn expect_integer(data: &[u8]) -> Result<(&[u8], Integer), ParseError> {
    let (rest, value) = expect_type(data, DataType::Integer)?;

    Ok((rest, Integer(value)))
}

pub fn expect_boolean(data: &[u8]) -> Result<(&[u8], Boolean), ParseError> {
    let (rest, value) = expect_type(data, DataType::Boolean)?;
    if value.len() != 1 {
        return Err(ParseError::InvalidLength);
    }

    Ok((rest, Boolean(value[0])))
}

pub fn expect_generalized_time(data: &[u8]) -> Result<(&[u8], GeneralizedTime), ParseError> {
    let (rest, value) = expect_type(data, DataType::GeneralizedTime)?;

    Ok((rest, GeneralizedTime(value)))
}

pub fn expect_utc_time(data: &[u8]) -> Result<(&[u8], UTCTime), ParseError> {
    let (rest, value) = expect_type(data, DataType::UTCTime)?;

    Ok((rest, UTCTime(value)))
}

pub fn expect_bit_string(data: &[u8]) -> Result<(&[u8], BitString), ParseError> {
    let (rest, value) = expect_type(data, DataType::BitString)?;

    Ok((rest, BitString(value)))
}

pub fn expect_octet_string(data: &[u8]) -> Result<(&[u8], OctetString), ParseError> {
    let (rest, value) = expect_type(data, DataType::OctetString)?;

    Ok((rest, OctetString(value)))
}

pub fn expect_object_identifier(data: &[u8]) -> Result<(&[u8], ObjectIdentifierRef), ParseError> {
    let (rest, inner) = expect_type(data, DataType::ObjectIdentifierRef)?;

    Ok((rest, ObjectIdentifierRef(inner)))
}

pub fn take_any(data: &[u8]) -> Result<(&[u8], Any), ParseError> {
    let (rest, tag, data) = get_tlv(data)?;
    Ok((rest, Any { tag, data }))
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
}
