use crate::generate::der::Data;

use super::super::{
    der::{DataType, ObjectIdentifier, ToDer},
    error::EncodingError,
};

#[derive(Clone)]
pub struct AlgorithmIdentifier {
    algorithm_identifier: ObjectIdentifier,
    parameters: Data, // any type
}

impl AlgorithmIdentifier {
    pub fn new(algorithm_identifier: ObjectIdentifier, parameters: Data) -> Self {
        Self {
            algorithm_identifier,
            parameters,
        }
    }
    // todo allow mutating parameters after construction
}

impl ToDer for AlgorithmIdentifier {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut algorithm_identifier = self.algorithm_identifier.to_der()?;
        let params = self.parameters.to_der()?;
        algorithm_identifier.extend_from_slice(&params);

        Ok(algorithm_identifier)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}
