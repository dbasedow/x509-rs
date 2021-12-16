use super::super::error::EncodingError;
use super::{DataType, ToDer};

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
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = Vec::with_capacity(self.data.len() + 1);
        res.push(self.padding_bits);
        res.extend_from_slice(&self.data);

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::BitString.into()
    }
}
