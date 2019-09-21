use crate::{Error, parse_der};
use crate::der::{Value, ObjectIdentifier};
use crate::extensions::GeneralName;

#[derive(Debug)]
pub struct AuthorityInfoAccess<'a>(Vec<Value<'a>>);

impl<'a> AuthorityInfoAccess<'a> {
    pub fn new(data: &'a [u8]) -> Result<AuthorityInfoAccess<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(AuthorityInfoAccess(s));
        }

        Err(Error::X509Error)
    }

    pub fn access_descriptions(&'a self) -> Result<Vec<AccessDescription<'a>>, Error> {
        let mut descriptions = Vec::with_capacity(self.0.len());
        for d in &self.0 {
            descriptions.push(AccessDescription::new(d)?);
        }
        Ok(descriptions)
    }
}

#[derive(Debug)]
pub enum AccessDescription<'a> {
    CaIssuers(GeneralName<'a>),
    Ocsp(GeneralName<'a>),
}

const AUTHORITY_INFO_ACCESS_OCSP_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 48, 1]);
const AUTHORITY_INFO_ACCESS_CA_ISSUERS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 48, 2]);

impl<'a> AccessDescription<'a> {
    fn new(value: &'a Value<'a>) -> Result<AccessDescription<'a>, Error> {
        if let Value::Sequence(seq, _) = value {
            if let Value::ObjectIdentifier(oid) = &seq[0] {
                match oid {
                    AUTHORITY_INFO_ACCESS_OCSP_OID => return Ok(AccessDescription::Ocsp(GeneralName::new(&seq[1])?)),
                    AUTHORITY_INFO_ACCESS_CA_ISSUERS_OID => return Ok(AccessDescription::CaIssuers(GeneralName::new(&seq[1])?)),
                    _ => unimplemented!("{}", oid),
                }
            }
        }

        Err(Error::X509Error)
    }
}
