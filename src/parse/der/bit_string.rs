use super::super::error::ParseError;
use super::{expect_type, DataType};
use crate::error::Error;
use std::fmt::Debug;

#[derive(PartialEq)]
pub struct BitStringRef<'a>(&'a [u8]);

impl<'a> Debug for BitStringRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BitString ({} bits)", self.bit_len())
    }
}

impl<'a> BitStringRef<'a> {
    pub fn bit_at(&self, index: usize) -> Result<bool, Error> {
        // First Byte contains amount of padding in bits
        if index + 1 > self.bit_len() {
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

    pub fn bit_len(&self) -> usize {
        (self.0.len() - 1) * 8 - self.0[0] as usize
    }
}

pub fn expect_bit_string(data: &[u8]) -> Result<(&[u8], BitStringRef), ParseError> {
    let (rest, value) = expect_type(data, DataType::BitString)?;

    Ok((rest, BitStringRef(value)))
}
