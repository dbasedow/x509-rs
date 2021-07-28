use crate::{
    der::{
        encode_tlv, expect_object_identifier, expect_sequence, take_any, AnyRef, DataType,
        ObjectIdentifier, ObjectIdentifierRef, ToDer,
    },
    error::ParseError,
};

use super::expect_empty;

#[derive(Debug)]
pub struct AlgorithmidentifierRef<'a> {
    algorithm_identifier: ObjectIdentifierRef<'a>,
    parameters: AnyRef<'a>,
}

pub fn parse_algorithm_identifier(
    data: &[u8],
) -> Result<(&[u8], AlgorithmidentifierRef), ParseError> {
    let (rest, inner) = expect_sequence(data)?;
    let (inner, algorithm_identifier) = expect_object_identifier(inner)?;
    let (inner, parameters) = take_any(inner)?;
    expect_empty(inner)?;
    Ok((
        rest,
        AlgorithmidentifierRef {
            algorithm_identifier,
            parameters,
        },
    ))
}

pub struct AlgorithmIdentifier {
    algorithm_identifier: ObjectIdentifier,
    parameters: Box<dyn ToDer>, // any type
}

impl ToDer for AlgorithmIdentifier {
    fn to_der(&self) -> Vec<u8> {
        let mut algorithm_identifier = self.algorithm_identifier.to_der();
        let params = self.parameters.to_der();
        algorithm_identifier.extend_from_slice(&params);

        encode_tlv(DataType::Sequence.into(), &algorithm_identifier)
    }
}
