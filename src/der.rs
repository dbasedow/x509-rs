use std::fmt::{self, Display, Formatter, Debug};
use chrono::prelude::*;
use crate::error::{Error, ParseError};
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectIdentifier<'a>(pub &'a [u8]);

impl<'a> ObjectIdentifier<'a> {
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

    pub fn from_str(s: &str) -> Result<Vec<u8>, ()> {
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
        Ok(data)
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

impl<'a> Display for ObjectIdentifier<'a> {
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

impl<'a> Debug for ObjectIdentifier<'a> {
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
    pub fn to_i64(&self) -> i64 {
        let data = self.0;

        let mut res: i64 = 0;
        let a = data[0] as i8;
        res += a as i64;

        for &octet in &data[1..] {
            res = res << 8;
            res = res | octet as i64;
        }
        res
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
        let u16s: Vec<u16> = self.0.chunks(2).map(|a| u16::from_be_bytes([a[0], a[1]])).collect();
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
            let factor = if data[10] == 0x2d { // '-'
                -1
            } else { 1 };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        } else if data.len() == 19 {
            let hour_offset = ascii_slice_to_u32(&data[13..15])?;
            let minute_offset = ascii_slice_to_u32(&data[16..18])?;
            let factor = if data[12] == 0x2d { // '-'
                -1
            } else { 1 };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        } else {
            utc_offset = 0;
        }

        let offset = FixedOffset::east(utc_offset);
        let dt = offset.ymd(year as i32, month, day).and_hms(hour, minute, second);

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
        if data[14] == 0x2e { // '.'
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
        if data[data.len() - 1] == 0x5a { // 'Z'
            utc_offset = 0;
        } else {
            let data = &data[data.len() - 6..];
            let hour_offset = ascii_slice_to_u32(&data[1..3])?;
            let minute_offset = ascii_slice_to_u32(&data[3..5])?;
            let factor = if data[0] == 0x2d { // '-'
                -1
            } else { 1 };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        }

        let offset = FixedOffset::east(utc_offset);
        let dt = offset.ymd(year as i32, month, day).and_hms_nano(hour, minute, second, nanos);

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

#[derive(Debug, PartialEq)]
pub enum Value<'a> {
    Boolean(Boolean),
    Integer(Integer<'a>),
    BitString(BitString<'a>),
    OctetString(&'a [u8]),
    Null,
    ObjectIdentifier(ObjectIdentifier<'a>),
    Sequence(Vec<Value<'a>>, &'a [u8]),
    // sequence, and raw slice
    UTCTime(UTCTime<'a>),
    GeneralizedTime(GeneralizedTime<'a>),
    PrintableString(PrintableString<'a>),
    VisibleString(VisibleString<'a>),
    T61String(T61String<'a>),
    IA5String(IA5String<'a>),
    Utf8String(Utf8String<'a>),
    BMPString(BMPString<'a>),
    Set(Vec<Value<'a>>),
    ContextSpecific(u8, Box<Value<'a>>),
    ContextSpecificRaw(u8, &'a [u8]),
}

impl<'a> Display for Value<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            Value::Boolean(b) => write!(f, "{:?}", b),
            Value::Integer(b) => write!(f, "{:?}", b),
            Value::Utf8String(s) => write!(f, "{}", s),
            Value::OctetString(s) => write!(f, "{:?}", s),
            Value::PrintableString(s) => write!(f, "{}", s),
            Value::VisibleString(s) => write!(f, "{}", s),
            Value::IA5String(s) => write!(f, "{}", s),
            Value::T61String(s) => write!(f, "{}", s),
            Value::BMPString(s) => write!(f, "{}", s),
            v => write!(f, "display not implemented {:?}", v),
        }
    }
}

fn parse_object_identifier(data: &[u8]) -> Result<Value, Error> {
    if data.len() < 1 {
        return Err(Error::ParseError(ParseError::MalformedData));
    }


    Ok(Value::ObjectIdentifier(ObjectIdentifier(data)))
}

fn parse_integer(data: &[u8]) -> Result<Value, Error> {
    Ok(Value::Integer(Integer(data)))
}

fn parse_sequence(data: &[u8]) -> Result<Vec<Value>, Error> {
    let mut data = &data[..];
    let mut elements: Vec<Value> = Vec::new();

    while data.len() > 0 {
        //let (tlv, consumed) = get_tlv(data)?;
        let (value, consumed) = parse_der(&data)?;
        elements.push(value);
        data = &data[consumed..];
    }

    Ok(elements)
}

fn parse_set(data: &[u8]) -> Result<Value, Error> {
    let mut data = &data[..];
    let mut elements: Vec<Value> = Vec::new();

    while data.len() > 0 {
        //let (tlv, consumed) = get_tlv(data)?;
        let (value, consumed) = parse_der(&data)?;
        elements.push(value);
        data = &data[consumed..];
    }

    Ok(Value::Set(elements))
}

fn parse_utc_time(data: &[u8]) -> Result<Value, Error> {
    Ok(Value::UTCTime(UTCTime(data)))
}

fn parse_generalized_time(data: &[u8]) -> Result<Value, Error> {
    Ok(Value::GeneralizedTime(GeneralizedTime(data)))
}

fn parse_boolean(data: &[u8]) -> Result<Value, Error> {
    if data.len() != 1 {
        return Err(Error::ParseError(ParseError::InvalidLength));
    }
    Ok(Value::Boolean(Boolean(data[0])))
}

pub fn parse_der(data: &[u8]) -> Result<(Value, usize), Error> {
    let (tlv, consumed) = get_tlv(data)?;
    if tlv.is_context_specific() {
        if tlv.is_constructed_type() {
            let (v, _) = parse_der(&tlv.value)?;
            return Ok((Value::ContextSpecific(tlv.get_data_type(), Box::new(v)), consumed));
        } else {
            return Ok((Value::ContextSpecificRaw(tlv.get_data_type(), &tlv.value), consumed));
        }
    }

    let value = match tlv.get_data_type() {
        0x01 => parse_boolean(&tlv.value)?,
        0x02 => parse_integer(&tlv.value)?,
        0x03 => Value::BitString(BitString(&tlv.value)),
        0x04 => Value::OctetString(&tlv.value),
        0x05 => Value::Null,
        0x06 => parse_object_identifier(&tlv.value)?,
        0x0c => Value::Utf8String(Utf8String(tlv.value)),
        0x10 => Value::Sequence(parse_sequence(&tlv.value)?, &data[..consumed]),
        0x11 => parse_set(&tlv.value)?,
        0x13 => Value::PrintableString(PrintableString(tlv.value)),
        0x14 => Value::T61String(T61String(tlv.value)),
        0x16 => Value::IA5String(IA5String(tlv.value)),
        0x17 => parse_utc_time(&tlv.value)?,
        0x18 => parse_generalized_time(&tlv.value)?,
        0x1a => Value::VisibleString(VisibleString(tlv.value)),
        0x1e => Value::BMPString(BMPString(tlv.value)),
        t => return Err(Error::ParseError(ParseError::UnsupportedTag(t))),
    };
    Ok((value, consumed))
}


struct TLV<'a> {
    tag: u8,
    value: &'a [u8],
}

impl<'a> TLV<'a> {
    fn get_data_type(&self) -> u8 {
        self.tag & 0x1f
    }

    fn is_constructed_type(&self) -> bool {
        self.tag & 0x20 == 0x20
    }

    fn is_context_specific(&self) -> bool {
        self.tag & 0x80 == 0x80
    }
}

fn get_tlv(data: &[u8]) -> Result<(TLV, usize), Error> {
    if data.len() < 2 {
        // we need at least a tag and a length (which may be 0)
        return Err(Error::ParseError(ParseError::MalformedData));
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
            return Err(Error::ParseError(ParseError::InvalidLength));
        }
        if length_length + 2 > data.len() {
            return Err(Error::ParseError(ParseError::InvalidLength));
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
        return Err(Error::ParseError(ParseError::InvalidLength));
    }

    Ok((TLV {
        tag,
        value: &data[consumed..consumed + length],
    }, consumed + length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_ascii_slice_to_u32() {
        let d: Vec<u8> = "12345".bytes().collect();
        assert_eq!(12345, ascii_slice_to_u32(&d).unwrap());
    }

    #[test]
    fn test_parse_object_identifier() {
        let d = hex::decode("2a864886f70d").unwrap();
        let res = parse_object_identifier(&d);
        assert!(res.is_ok());
        let oid = res.ok().unwrap();
        if let Value::ObjectIdentifier(oid) = oid {
            assert_eq!("1.2.840.113549", format!("{}", oid));
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_parse_integer() {
        let d: Vec<u8> = vec![0x80];
        let res = parse_integer(&d);
        assert!(res.is_ok());
        assert_eq!(format!("{}", Value::Integer(Integer(&d))), "-128");

        let d: Vec<u8> = vec![0xFF, 0x7F];
        let res = parse_integer(&d);
        assert!(res.is_ok());
        assert_eq!(format!("{}", Value::Integer(Integer(&d))), "-129");

        let d: Vec<u8> = vec![0x00, 0x80];
        let res = parse_integer(&d);
        assert!(res.is_ok());
        assert_eq!(format!("{}", Value::Integer(Integer(&d))), "128");
        assert_eq!(format!("{}", Integer(&d).to_big_int()), "128");

        let d: Vec<u8> = vec![0x00, 0xa9, 0x98, 0xea, 0x4e, 0xa1, 0xd9, 0x30, 0xf5, 0x64, 0x7f];
        let res = parse_integer(&d);
        assert!(res.is_ok());
        assert_eq!(format!("{}", Integer(&d).to_big_int()), "800900724314181152892031");
    }

    #[test]
    fn test_get_tlv() {
        let d = hex::decode("06062a864886f70d").unwrap();
        let res = get_tlv(&d);
        assert!(res.is_ok());
        let (tlv, consumed) = res.ok().unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(tlv.tag, 0x06);
        assert_eq!(hex::encode(tlv.value), "2a864886f70d");
    }

    #[test]
    fn test_parse_der() {
        let d = hex::decode("308202bc308201a4a003020102020404c5fefc300d06092a864886f70d01010b0500302e312c302a0603550403132359756269636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f32303530303930343030303030305a306d310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3126302406035504030c1d59756269636f205532462045452053657269616c2038303038343733323059301306072a8648ce3d020106082a8648ce3d030107034200041cd8da7611a3f5ef1f885e950ba65d80e334855391584bd47f5b719c53235c2421e4e399bdb5736782419093576661493c914c2e6724df9394fcfa7dea8b1804a36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e313013060b2b0601040182e51c0201010404030205203021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b0500038201010077184cef752d1a05f30a5385dc2d86f8fac0637170b02262a5195cf5fed036fe00654e0d2915bc45529a3f895e6ac1ccd41e977156e00ba93a06e0ac99a6716584059c974a9450b58725d8b4cd534f88cfd59bc8734dd70409f726c5c23eb4f3106ea0d442d2b1bcc2061b302e2eb3245a76dddd60e55d422d1c7da92c541d9534a9f0fadb505162a866c3c7b6ecc5c7c3656b32d005ea755b64f414238d1441bbc7f97e65c7cd853d776b301b6aeac9d89d3f7dfe87d0f5c93fa87e39b9dee317f3d3ef2e8dfb560d44a1f686a255161ffad81a9bfb7338ac84537f15da5895d75cccc87296ad788ad007f20e06f9f24cb61d2ae7fc0804e4c5bfa1783f0977").unwrap();
        let res = parse_der(&d);
        assert!(res.is_ok());
        let (_value, consumed) = res.ok().unwrap();
        assert_eq!(consumed, 704);
    }

    #[test]
    fn test_parse_der_sequence() {
        let d = hex::decode("3020170d3134303830313030303030305a180f32303530303930343030303030305a").unwrap();
        let res = parse_der(&d);
        assert!(res.is_ok());
    }

    #[test]
    fn test_parse_der_object_id() {
        let d = hex::decode("06062a864886f70d").unwrap();
        let res = parse_der(&d);
        assert!(res.is_ok());
        if let (Value::ObjectIdentifier(value), _) = res.ok().unwrap() {
            assert_eq!("1.2.840.113549", format!("{}", value));
        } else {
            panic!("wrong value type");
        }
    }

    #[test]
    fn test_encode_oid_part() {
        let d = encode_oid_part(128);
        assert_eq!(&[0x81, 0x00], &d[..]);
        let d = encode_oid_part(311);
        assert_eq!(&[0x82, 0x37], &d[..]);
    }
}
