use super::super::error::ParseError;
use std::fmt::{self, Debug, Formatter};

use super::{expect_type, DataType};

#[derive(PartialEq)]
pub struct IntegerRef<'a>(&'a [u8]);

impl<'a> IntegerRef<'a> {
    pub fn to_i64(&self) -> Result<i64, ParseError> {
        if self.is_big_int() {
            // can't fit value in i64
            return Err(ParseError::InvalidLength);
        }

        let data = self.0;
        let mut res: i64 = 0;
        let a = data[0] as i8;
        res += a as i64;

        for &octet in &data[1..] {
            res = res << 8;
            res = res | octet as i64;
        }
        Ok(res)
    }

    pub fn is_big_int(&self) -> bool {
        self.0.len() > 8
    }

    pub fn to_big_int(&self) -> num_bigint::BigInt {
        num_bigint::BigInt::from_signed_bytes_be(self.0)
    }
}

impl<'a> Debug for IntegerRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let i = self.to_big_int();
        write!(f, "{}", i)
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
