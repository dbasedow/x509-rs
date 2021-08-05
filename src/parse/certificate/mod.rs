mod algorithm_identifier;
mod extensions;
mod name;
mod subject_public_key_info;
mod validity;
mod version;

pub use algorithm_identifier::{parse_algorithm_identifier, AlgorithmidentifierRef};
pub use extensions::{ExtensionRef, ExtensionsRef};
pub use name::NameRef;
pub use subject_public_key_info::SubjectPublicKeyInfoRef;
pub use validity::ValidityRef;
pub use version::{parse_version, Version};

use super::error::ParseError;

pub fn expect_empty(data: &[u8]) -> Result<(), ParseError> {
    if !data.is_empty() {
        return Err(ParseError::MalformedData);
    }

    Ok(())
}
