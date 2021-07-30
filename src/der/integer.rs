use crate::error::{EncodingError, ParseError};
use std::fmt::{self, Debug, Formatter};

use super::{expect_type, DataType, ToDer};

#[derive(PartialEq)]
pub struct Integer(Vec<u8>);

#[derive(PartialEq)]
pub struct IntegerRef<'a>(&'a [u8]);

impl<'a> IntegerRef<'a> {
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

impl<'a> Debug for IntegerRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let i = self.to_i64();
        write!(f, "{:#?}", i)
    }
}

pub fn expect_integer(data: &[u8]) -> Result<(&[u8], IntegerRef), ParseError> {
    let (rest, value) = expect_type(data, DataType::Integer)?;

    Ok((rest, IntegerRef(value)))
}

#[test]
fn test_parse_int() {
    let i = IntegerRef(&[0x00]);
    assert_eq!(i.to_i64().unwrap(), 0);

    let i = IntegerRef(&[0x7f]);
    assert_eq!(i.to_i64().unwrap(), 127);

    let i = IntegerRef(&[0x00, 0x80]);
    assert_eq!(i.to_i64().unwrap(), 128);

    let i = IntegerRef(&[0x01, 0x00]);
    assert_eq!(i.to_i64().unwrap(), 256);

    let i = IntegerRef(&[0x80]);
    assert_eq!(i.to_i64().unwrap(), -128);

    let i = IntegerRef(&[0xff, 0x7f]);
    assert_eq!(i.to_i64().unwrap(), -129);

    let i = IntegerRef(&[0xff]);
    assert_eq!(i.to_i64().unwrap(), -1);
}

impl Integer {
    pub fn from_i64(i: i64) -> Self {
        let bs = i.to_be_bytes();
        let encoded = encode_integer(&bs);

        Self(encoded)
    }
}

impl ToDer for Integer {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(self.0.clone())
    }

    fn get_tag(&self) -> u8 {
        DataType::Integer.into()
    }
}

fn encode_integer(bs: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();

    let is_negative = (bs[0] & 0x80) == 0x80;
    if is_negative {
        // find first byte that is not 0xff
        let pos = bs.iter().position(|b| *b != 0xff);
        if let Some(pos) = pos {
            // if first bit is 0, add 0xff in front
            if (bs[pos] & 0x80) != 0x80 {
                res.push(0xff);
            }
            res.extend_from_slice(&bs[pos..]);
        } else {
            res.push(0xff);
        }
    } else {
        // find first byte that is not 0x00
        let pos = bs.iter().position(|b| *b != 0x00);
        if let Some(pos) = pos {
            // if first bit is 1, add 0x00 in front
            if (bs[pos] & 0x80) == 0x80 {
                res.push(0x00);
            }
            res.extend_from_slice(&bs[pos..]);
        } else {
            res.push(0x00);
        }
    }

    res
}

#[test]
fn test_encode_integer_i64() {
    assert_eq!(Integer::from_i64(1).0, &[0x01]);
    assert_eq!(Integer::from_i64(-128).0, &[0x80]);
    assert_eq!(Integer::from_i64(0).0, &[0x00]);
    assert_eq!(Integer::from_i64(127).0, &[0x7f]);
    assert_eq!(Integer::from_i64(128).0, &[0x00, 0x80]);
    assert_eq!(Integer::from_i64(256).0, &[0x01, 0x00]);
    assert_eq!(Integer::from_i64(-129).0, &[0xff, 0x7f]);
    assert_eq!(Integer::from_i64(-1).0, &[0xff]);
}
