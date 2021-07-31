use crate::{error::ParseError, Error};

use super::{expect_type, DataType, ToDer};

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

pub struct BitString {
    data: Vec<u8>,
    padding_bits: u8,
}

impl BitString {
    pub fn new(data: Vec<u8>, used_bits: usize) -> Self {
        let mut byte_len = used_bits / 8;
        let padding_bits = (used_bits % 8) as u8;
        if padding_bits != 0 {
            byte_len += 1;
        }

        assert_eq!(data.len(), byte_len);

        Self { data, padding_bits }
    }
}

impl ToDer for BitString {
    fn encode_inner(&self) -> Result<Vec<u8>, crate::error::EncodingError> {
        let mut res = Vec::with_capacity(self.data.len() + 1);
        res.push(self.padding_bits);
        res.extend_from_slice(&self.data);

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::BitString.into()
    }
}
