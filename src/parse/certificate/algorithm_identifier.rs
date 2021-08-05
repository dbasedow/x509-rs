use super::super::der::{
    expect_object_identifier, expect_sequence, take_any, AnyRef, ObjectIdentifierRef,
};
use super::super::error::ParseError;
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
