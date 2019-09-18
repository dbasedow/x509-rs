use num_bigint::BigInt;
use crate::der::Value;
use crate::{Error, parse_der};
use crate::extensions::GeneralName;

#[derive(Debug)]
pub struct AuthorityKeyIdentifier<'a>(Vec<Value<'a>>);

impl<'a> AuthorityKeyIdentifier<'a> {
    pub fn new(data: &'a [u8]) -> Result<AuthorityKeyIdentifier<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(AuthorityKeyIdentifier(s));
        }

        Err(Error::X509Error)
    }

    pub fn key_identifier(&self) -> Result<Option<&'a [u8]>, Error> {
        for v in &self.0 {
            if let Value::ContextSpecificRaw(0, content) = v {
                return Ok(Some(content));
            }
        }
        Ok(None)
    }

    pub fn authority_cert_issuer(&'a self) -> Result<Option<GeneralName<'a>>, Error> {
        for v in &self.0 {
            if let Value::ContextSpecific(1, content) = v {
                return Ok(Some(GeneralName::new(content)?));
            }
        }
        Ok(None)
    }

    pub fn authority_cert_serial_number(&self) -> Result<Option<BigInt>, Error> {
        for v in &self.0 {
            if let Value::ContextSpecificRaw(2, content) = v {
                let serial = BigInt::from_signed_bytes_be(content);
                return Ok(Some(serial));
            }
        }
        Ok(None)
    }
}
