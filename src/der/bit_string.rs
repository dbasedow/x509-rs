use crate::{Error, error::ParseError};

use super::{DataType, expect_type};


#[derive(Debug, PartialEq)]
pub struct BitStringRef<'a>(&'a [u8]);

impl<'a> BitStringRef<'a> {
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


pub fn expect_bit_string(data: &[u8]) -> Result<(&[u8], BitStringRef), ParseError> {
    let (rest, value) = expect_type(data, DataType::BitString)?;

    Ok((rest, BitStringRef(value)))
}
