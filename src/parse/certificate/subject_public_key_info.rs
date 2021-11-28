use super::super::{
    der::{expect_bit_string, expect_sequence, BitStringRef},
    error::ParseError,
};
use super::{expect_empty, parse_algorithm_identifier, AlgorithmidentifierRef};

#[derive(Debug)]
pub struct SubjectPublicKeyInfoRef<'a> {
    algorithm: AlgorithmidentifierRef<'a>,
    subject_public_key: BitStringRef<'a>,
}

impl<'a> SubjectPublicKeyInfoRef<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, algorithm) = parse_algorithm_identifier(data)?;
        let (data, subject_public_key) = expect_bit_string(data)?;
        expect_empty(data)?;
        let spki = Self {
            algorithm,
            subject_public_key,
        };

        Ok((rest, spki))
    }

    pub fn algorithm_identifier(&self) -> &AlgorithmidentifierRef {
        &self.algorithm
    }

    pub fn subject_public_key(&self) -> &BitStringRef {
        &self.subject_public_key
    }
}
