mod algorithm_identifier;
mod name;
mod subject_public_key_info;
mod validity;
mod version;

pub use algorithm_identifier::{parse_algorithm_identifier, AlgorithmidentifierRef, AlgorithmIdentifier};
pub use name::{AttributeTypeAndValue, NameRef, Name, DistinguishedName, RelativeDistinguishedName};
pub use subject_public_key_info::{SubjectPublicKeyInfoRef, SubjectPublicKeyInfo};
pub use validity::{ValidityRef, Validity};
pub use version::{parse_version, Version};

use crate::error::ParseError;

pub fn expect_empty(data: &[u8]) -> Result<(), ParseError> {
    if !data.is_empty() {
        return Err(ParseError::MalformedData);
    }

    Ok(())
}
