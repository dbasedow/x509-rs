use super::super::error::EncodingError;
use super::{DataType, ToDer};

#[derive(PartialEq, Clone)]
pub struct Integer(Vec<u8>);

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
