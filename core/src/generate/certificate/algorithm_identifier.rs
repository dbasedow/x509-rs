use super::super::{
    der::{DataType, ObjectIdentifier, ToDer},
    error::EncodingError,
};

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
        DataType::Sequence.constructed()
    }
}
