use crate::{Error, parse_der};
use crate::extensions::GeneralName;
use crate::der::Value;

#[derive(Debug)]
pub struct SubjectAlternativeNames<'a>(Vec<Value<'a>>);

impl<'a> SubjectAlternativeNames<'a> {
    pub fn new(data: &'a [u8]) -> Result<SubjectAlternativeNames<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(SubjectAlternativeNames(s));
        }

        Err(Error::X509Error)
    }

    pub fn names(&self) -> Result<Vec<GeneralName>, Error> {
        let mut sans = Vec::with_capacity(self.0.len());
        for v in &self.0 {
            sans.push(GeneralName::new(&v)?);
        }
        return Ok(sans);
        Err(Error::X509Error)
    }
}
