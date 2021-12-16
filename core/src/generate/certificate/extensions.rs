use crate::generate::error::EncodingError;
use super::super::der::{Boolean, DataType, ObjectIdentifier, OctetString, ToDer};
use std::usize;

pub trait IntoExtension {
    fn extension_id(&self) -> ObjectIdentifier;
    fn critical(&self) -> Boolean;
    fn value(&self) -> OctetString;
}

pub struct Extension {
    extension_id: ObjectIdentifier,
    critical: Boolean,
    value: OctetString,
}

impl Extension {
    pub fn new(extension_id: ObjectIdentifier, critical: Boolean, value: OctetString) -> Self {
        Self {
            extension_id,
            critical,
            value,
        }
    }
}

impl ToDer for Extension {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = self.extension_id.to_der()?;
        // CRICITAL is marked DEFAULT FALSE, so we only write it when it's true
        if self.critical.to_bool() {
            res.extend_from_slice(&self.critical.to_der()?);
        }
        res.extend_from_slice(&self.value.to_der()?);

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}

#[derive(Default)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    pub fn add(&mut self, extension: Extension) {
        self.0.push(extension);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl ToDer for Extensions {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = Vec::new();
        for ext in self.0.iter() {
            res.extend_from_slice(&ext.to_der()?);
        }

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}
