use crate::der::{ObjectIdentifier, Value};
use crate::{Error, parse_der};

#[derive(Debug)]
pub struct ExtendedKeyUsage<'a>(Vec<Value<'a>>);

impl<'a> ExtendedKeyUsage<'a> {
    pub fn new(data: &'a [u8]) -> Result<ExtendedKeyUsage<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(ExtendedKeyUsage(s));
        }

        Err(Error::X509Error)
    }

    pub fn key_purposes(&self) -> Result<Vec<KeyPurpose>, Error> {
        let mut purposes = Vec::with_capacity(self.0.len());
        for v in &self.0 {
            if let Value::ObjectIdentifier(oid) = v {
                purposes.push(KeyPurpose::from_oid(oid));
            } else {
                return Err(Error::X509Error);
            }
        }

        Ok(purposes)
    }
}

#[derive(Debug)]
pub enum KeyPurpose<'a> {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    Unknown(&'a ObjectIdentifier<'a>),
}

const KEY_PURPOSE_SERVER_AUTH_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 3, 1]);
const KEY_PURPOSE_CLIENT_AUTH_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 3, 2]);
const KEY_PURPOSE_CODE_SIGNING_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 3, 3]);
const KEY_PURPOSE_EMAIL_PROTECTION_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 3, 4]);
const KEY_PURPOSE_TIME_STAMPING_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 3, 8]);
const KEY_PURPOSE_OCSP_SIGNING_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 3, 9]);

impl<'a> KeyPurpose<'a> {
    pub fn from_oid(oid: &'a ObjectIdentifier<'a>) -> KeyPurpose<'a> {
        match oid {
            KEY_PURPOSE_SERVER_AUTH_OID => KeyPurpose::ServerAuth,
            KEY_PURPOSE_CLIENT_AUTH_OID => KeyPurpose::ClientAuth,
            KEY_PURPOSE_CODE_SIGNING_OID => KeyPurpose::CodeSigning,
            KEY_PURPOSE_EMAIL_PROTECTION_OID => KeyPurpose::EmailProtection,
            KEY_PURPOSE_TIME_STAMPING_OID => KeyPurpose::TimeStamping,
            KEY_PURPOSE_OCSP_SIGNING_OID => KeyPurpose::OcspSigning,
            o => KeyPurpose::Unknown(o),
        }
    }
}
