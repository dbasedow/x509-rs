use crate::der::{BitString, Value};
use crate::error::Error;
use crate::parse_der;

#[derive(Debug)]
pub struct KeyUsage<'a>(BitString<'a>);

impl<'a> KeyUsage<'a> {
    pub fn new(data: &'a [u8]) -> Result<KeyUsage<'a>, Error> {
        if let (Value::BitString(bs), _) = parse_der(data)? {
            return Ok(KeyUsage(bs));
        }

        Err(Error::ParseError)
    }

    pub fn digital_signature(&self) -> Result<bool, Error> {
        self.0.bit_at(0)
    }

    pub fn non_repudiation(&self) -> Result<bool, Error> {
        self.0.bit_at(1)
    }

    pub fn key_encipherment(&self) -> Result<bool, Error> {
        self.0.bit_at(2)
    }

    pub fn data_encipherment(&self) -> Result<bool, Error> {
        self.0.bit_at(3)
    }

    pub fn key_agreement(&self) -> Result<bool, Error> {
        self.0.bit_at(4)
    }

    pub fn key_cert_sign(&self) -> Result<bool, Error> {
        self.0.bit_at(5)
    }

    pub fn crl_sign(&self) -> Result<bool, Error> {
        self.0.bit_at(6)
    }
}
