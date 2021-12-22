use super::super::error::EncodingError;
use super::{DataType, ToDer};
pub use crate::parse::der::ObjectIdentifier;
use crate::parse::der::ObjectIdentifierRef;

impl ToDer for ObjectIdentifier {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(self.0.clone())
    }

    fn get_tag(&self) -> u8 {
        DataType::ObjectIdentifier.into()
    }
}

impl<'a> From<&'a ObjectIdentifier> for ObjectIdentifierRef<'a> {
    fn from(oid: &'a ObjectIdentifier) -> Self {
        Self(&oid.0)
    }
}
