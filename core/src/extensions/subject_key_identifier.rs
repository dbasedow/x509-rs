use crate::error::Error;

#[derive(Debug)]
pub struct SubjectKeyIdentifier<'a>(&'a [u8]);

impl<'a> SubjectKeyIdentifier<'a> {
    pub fn new(data: &'a [u8]) -> Result<SubjectKeyIdentifier<'a>, Error> {
        Ok(SubjectKeyIdentifier(data))
    }

    pub fn key_identifier(&self) -> Result<Option<&'a [u8]>, Error> {
        Ok(Some(self.0))
    }
}
