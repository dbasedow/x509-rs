use crate::error::ParseError;
use std::fmt::{self, Debug, Formatter};

use super::{expect_type, DataType};

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
