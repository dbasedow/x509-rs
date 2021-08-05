use super::super::{
    der::{DataType, ObjectIdentifier, ToDer},
    error::EncodingError,
};

pub struct AttributeTypeAndValue {
    typ: ObjectIdentifier,
    value: Box<dyn ToDer>,
}

impl AttributeTypeAndValue {
    pub fn new(typ: ObjectIdentifier, value: Box<dyn ToDer>) -> Self {
        Self { typ, value }
    }
}

impl ToDer for AttributeTypeAndValue {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut inner = self.typ.to_der()?;
        inner.extend_from_slice(&self.value.to_der()?);

        Ok(inner)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}

#[derive(Default)]
pub struct RelativeDistinguishedName {
    values: Vec<AttributeTypeAndValue>,
}

impl RelativeDistinguishedName {
    pub fn insert(&mut self, inner: AttributeTypeAndValue) {
        if self.values.len() > 0 {
            unimplemented!("this is not supported");
        }
        self.values.push(inner);
    }
}

impl ToDer for RelativeDistinguishedName {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = Vec::new();
        for value in self.values.iter() {
            res.extend_from_slice(&value.to_der()?);
        }

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Set.constructed()
    }
}

#[derive(Default)]
pub struct DistinguishedName(Vec<RelativeDistinguishedName>);

impl DistinguishedName {
    pub fn push(&mut self, rdn: RelativeDistinguishedName) {
        self.0.push(rdn);
    }
}

impl ToDer for DistinguishedName {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = Vec::new();
        for dn in self.0.iter() {
            res.extend_from_slice(&dn.to_der()?);
        }

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}

pub enum Name {
    DistinguishedName(DistinguishedName),
}

impl ToDer for Name {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        match self {
            Name::DistinguishedName(dn) => dn.encode_inner(),
        }
    }

    fn get_tag(&self) -> u8 {
        match self {
            Name::DistinguishedName(dn) => dn.get_tag(),
        }
    }
}
