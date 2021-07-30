use crate::{der::{
        expect_object_identifier, expect_sequence, take_any, AnyRef, DataType, ObjectIdentifier,
        ObjectIdentifierRef, ToDer,
    }, error::{EncodingError, ParseError}};

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

impl AlgorithmIdentifier {
    pub fn new(algorithm_identifier: ObjectIdentifier, parameters: Box<dyn ToDer>) -> Self {
        Self {
            algorithm_identifier,
            parameters,
        }
    }
}

impl ToDer for AlgorithmIdentifier {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut algorithm_identifier = self.algorithm_identifier.to_der()?;
        let params = self.parameters.to_der()?;
        algorithm_identifier.extend_from_slice(&params);
        
        Ok(algorithm_identifier)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.into()
    }
}
