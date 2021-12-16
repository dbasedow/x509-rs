use super::super::der::{
    expect_object_identifier, expect_sequence, take_any, AnyRef, ObjectIdentifierRef,
};
use super::super::error::ParseError;
use super::expect_empty;

#[derive(Debug)]
pub struct AlgorithmidentifierRef<'a> {
    algorithm_identifier: ObjectIdentifierRef<'a>,
    parameters: Option<AnyRef<'a>>,
}

impl<'a> AlgorithmidentifierRef<'a> {
    pub fn parameters(&self) -> &Option<AnyRef<'a>> {
        &self.parameters
    }

    pub fn algorithm_identifier(&self) -> &ObjectIdentifierRef {
        &self.algorithm_identifier
    }
}

pub fn parse_algorithm_identifier(
    data: &[u8],
) -> Result<(&[u8], AlgorithmidentifierRef), ParseError> {
    let (rest, inner) = expect_sequence(data)?;
    let (inner, algorithm_identifier) = expect_object_identifier(inner)?;
    // todo based on algorithm identifier there could be parameters or not
    let (inner, parameters) = if inner.len() != 0 {
        let (inner, parameters) = take_any(inner)?;
        (inner, Some(parameters))
    } else {
        (inner, None)
    };

    expect_empty(inner)?;
    Ok((
        rest,
        AlgorithmidentifierRef {
            algorithm_identifier,
            parameters,
        },
    ))
}
