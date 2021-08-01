mod algorithm_identifier;
mod extensions;
mod name;
mod subject_public_key_info;
mod validity;
mod version;

pub use algorithm_identifier::{
    parse_algorithm_identifier, AlgorithmIdentifier, AlgorithmidentifierRef,
};
pub use extensions::{ExtensionRef, ExtensionsRef, Extension, Extensions};
pub use name::{
    AttributeTypeAndValue, DistinguishedName, Name, NameRef, RelativeDistinguishedName,
};
pub use subject_public_key_info::{SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
pub use validity::{Validity, ValidityRef};
pub use version::{parse_version, Version};

use crate::error::ParseError;

pub fn expect_empty(data: &[u8]) -> Result<(), ParseError> {
    if !data.is_empty() {
        return Err(ParseError::MalformedData);
    }

    Ok(())
}
