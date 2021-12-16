use super::super::der::{DataType, ToDer};
use crate::generate::error::EncodingError;
use chrono::{DateTime, Utc};

pub struct Validity {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl Validity {
    pub fn new(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        Self {
            not_before,
            not_after,
        }
    }
}

impl ToDer for Validity {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = self.not_before.to_der()?;
        res.extend_from_slice(&self.not_after.to_der()?);

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}
