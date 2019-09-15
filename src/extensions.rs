use crate::der::{ObjectIdentifier, Value, parse_der, BitString};
use crate::error::Error;

const KEY_USAGE_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 15]);
const BASIC_CONSTRAINTS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 19]);

#[derive(Debug)]
pub enum ExtensionType<'a> {
    KeyUsage(KeyUsage<'a>),
    BasicConstraints(BasicConstraints<'a>),
    Unknown(&'a ObjectIdentifier<'a>, &'a [u8]),
}

impl<'a> ExtensionType<'a> {
    pub fn new(oid: &'a ObjectIdentifier, data: &'a [u8]) -> Result<ExtensionType<'a>, Error> {
        match oid {
            KEY_USAGE_OID => Ok(ExtensionType::KeyUsage(KeyUsage::new(data)?)),
            BASIC_CONSTRAINTS_OID => Ok(ExtensionType::BasicConstraints(BasicConstraints::new(data)?)),
            _ => Ok(ExtensionType::Unknown(oid, data)),
        }
    }
}

#[derive(Debug)]
pub struct KeyUsage<'a>(BitString<'a>);

impl<'a> KeyUsage<'a> {
    fn new(data: &'a [u8]) -> Result<KeyUsage<'a>, Error> {
        let (parsed, _) = parse_der(data)?;

        if let Value::BitString(bs) = parsed {
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

#[derive(Debug)]
pub struct BasicConstraints<'a>(Vec<Value<'a>>);

impl<'a> BasicConstraints<'a> {
    fn new(data: &'a [u8]) -> Result<BasicConstraints<'a>, Error> {
        let (parsed, _) = parse_der(data)?;

        if let Value::Sequence(s, _) = parsed {
            return Ok(BasicConstraints(s));
        }

        Err(Error::ParseError)
    }

    pub fn is_ca(&self) -> Result<bool, Error> {
        if !self.0.is_empty() {
            if let Value::Boolean(ca) = &self.0[0] {
                return Ok(ca.to_bool());
            } else {
                return Err(Error::X509Error);
            }
        }

        Ok(false)
    }

    pub fn path_len_constraint(&self) -> Result<Option<i64>, Error> {
        if self.0.is_empty() {
            // if sequence is empty this constraint doesn't make sense, since by default it's not a CA
            return Err(Error::X509Error);
        }
        if self.0.len() == 2 {
            if let Value::Integer(c) = &self.0[1] {
                return Ok(Some(c.to_i64()));
            } else {
                //it must be an integer, otherwise something is wrong
                return Err(Error::X509Error);
            }
        }
        Ok(None)
    }
}
