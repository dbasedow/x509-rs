mod version;

pub use version::{Version, parse_version};

use crate::error::ParseError;

pub fn expect_empty(data: &[u8]) -> Result<(), ParseError> {
    if !data.is_empty() {
        return Err(ParseError::MalformedData);
    }

    Ok(())
}
