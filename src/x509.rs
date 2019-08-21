use crate::der::{Value, ObjectIdentifier};
use crate::Error;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;
use chrono::{DateTime, FixedOffset};
use std::fmt::{self, Debug, Formatter, Display};

pub struct Certificate<'a>(Value<'a>);

pub enum Version {
    V1,
    V2,
    V3,
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Version::V1 => write!(f, "1"),
            Version::V2 => write!(f, "2"),
            Version::V3 => write!(f, "3"),
        }
    }
}

pub enum SignatureAlgorithm {
    Pkcs1Sha256Rsa,
}

impl TryFrom<i64> for Version {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Version::V1,
            1 => Version::V2,
            2 => Version::V3,
            n => unimplemented!("version {} not supported", n),
        })
    }
}

impl<'a> Certificate<'a> {
    pub fn from_value(value: Value<'a>) -> Certificate<'a> {
        Certificate(value)
    }

    pub fn serial(&self) -> Result<num_bigint::BigInt, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::Integer(serial) = &tbs_cert[1] {
            return Ok(serial.to_big_int());
        }
        Err(Error::X509Error)
    }

    pub fn version(&self) -> Result<Version, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::ContextSpecific(_, version) = &tbs_cert[0] {
            if let Value::Integer(version) = version.deref() {
                return Ok(version.to_i64().try_into()?);
            }
        }
        Err(Error::X509Error)
    }

    pub fn signature(&self) -> Result<&[u8], Error> {
        if let Value::Sequence(certificate, _) = &self.0 {
            if let Value::BitString(signature) = &certificate[2] {
                let (_, data) = signature.data();
                return Ok(data);
            }
        }
        Err(Error::X509Error)
    }

    pub fn valid_from(&self) -> Result<DateTime<FixedOffset>, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::Sequence(validty, _) = &tbs_cert[4] {
            return match &validty[0] {
                Value::UTCTime(dt) => dt.to_datetime(),
                Value::GeneralizedTime(dt) => dt.to_datetime(),
                _ => unimplemented!("validity must be either UTC or Generalized Time"),
            };
        }
        Err(Error::X509Error)
    }

    pub fn valid_to(&self) -> Result<DateTime<FixedOffset>, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::Sequence(validty, _) = &tbs_cert[4] {
            return match &validty[1] {
                Value::UTCTime(dt) => dt.to_datetime(),
                Value::GeneralizedTime(dt) => dt.to_datetime(),
                _ => unimplemented!("validity must be either UTC or Generalized Time"),
            };
        }
        Err(Error::X509Error)
    }

    pub fn issuer(&self) -> Result<Vec<RelativeDistinguishedName>, Error> {
        self.get_rdns_at_offset(3)
    }

    pub fn subject(&self) -> Result<Vec<RelativeDistinguishedName>, Error> {
        self.get_rdns_at_offset(5)
    }

    fn get_rdns_at_offset(&self, offset: usize) -> Result<Vec<RelativeDistinguishedName>, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::Sequence(entries, _) = &tbs_cert[offset] {
            let mut result: Vec<RelativeDistinguishedName> = Vec::with_capacity(entries.len());
            for e in entries {
                if let Value::Set(s) = e {
                    if let Value::Sequence(sub, _) = &s[0] {
                        if let Value::ObjectIdentifier(oid) = &sub[0] {
                            if let Some(rdn) = RelativeDistinguishedName::from_oid_and_string(&oid, &sub[1]) {
                                result.push(rdn);
                            }
                        }
                    }
                }
            }
            return Ok(result);
        }
        Err(Error::X509Error)
    }

    fn tbs_cert(&self) -> Result<&Vec<Value>, Error> {
        if let Value::Sequence(certificate, _) = &self.0 {
            if let Value::Sequence(tbs_cert, _) = &certificate[0] {
                return Ok(tbs_cert);
            }
        }
        Err(Error::X509Error)
    }

    pub fn raw_tbs_cert(&self) -> Result<&[u8], Error> {
        if let Value::Sequence(certificate, _) = &self.0 {
            if let Value::Sequence(_, raw) = &certificate[0] {
                return Ok(raw);
            }
        }
        Err(Error::X509Error)
    }

    pub fn public_key(&self) -> Result<&[u8], Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::Sequence(seq, _) = &tbs_cert[6] {
            if let Value::BitString(key) = &seq[1] {
                let (_, data) = key.data();
                return Ok(data);
            }
        }

        Err(Error::X509Error)
    }

    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm, Error> {
        if let Value::Sequence(certificate, _) = &self.0 {
            if let Value::Sequence(algorithm_identifier, _) = &certificate[0] {
                if let Value::ObjectIdentifier(oid) = &algorithm_identifier[0] {
                    //TODO find better way to match
                    match format!("{}", oid).as_ref() {
                        "1.2.840.113549.1.1.11" => return Ok(SignatureAlgorithm::Pkcs1Sha256Rsa),
                        _ => return Err(Error::X509Error),
                    }
                }
            }
        }
        Err(Error::X509Error)
    }

    pub fn extensions(&self) -> Result<Vec<Extension>, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::ContextSpecific(ctx, value) = tbs_cert.last().unwrap() {
            if *ctx == 3 {
                if let Value::Sequence(exts, _) = value.deref() {
                    let mut res: Vec<Extension> = Vec::with_capacity(exts.len());
                    for ext in exts {
                        if let Value::Sequence(ext, _) = ext {
                            if let Value::ObjectIdentifier(oid) = &ext[0] {
                                if let Value::Boolean(critical) = &ext[1] {
                                    if let Value::OctetString(data) = &ext[2] {
                                        let extension = Extension(oid.clone(), critical.to_bool(), data.clone());
                                        res.push(extension);
                                    }
                                } else {
                                    let critical = false;
                                    if let Value::OctetString(data) = &ext[1] {
                                        let extension = Extension(oid.clone(), critical, data.clone());
                                        res.push(extension);
                                    }
                                }
                            }
                        }
                    }
                    return Ok(res);
                }
            }
        }
        Err(Error::X509Error)
    }
}

pub struct Extension<'a>(ObjectIdentifier<'a>, bool, &'a [u8]);

impl<'a> Debug for Extension<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Extension: {} critical: {} data: {:x?}", self.0, self.1, self.2)
    }
}

impl<'a> Extension<'a> {
    pub fn data(&self) -> &[u8] {
        self.2
    }
}

pub enum RelativeDistinguishedName<'a> {
    CommonName(&'a Value<'a>),
    Country(&'a Value<'a>),
    Organization(&'a Value<'a>),
    OrganizationalUnit(&'a Value<'a>),
}

impl<'a> RelativeDistinguishedName<'a> {
    fn from_oid_and_string(oid: &ObjectIdentifier, value: &'a Value) -> Option<RelativeDistinguishedName<'a>> {
        match format!("{}", oid).as_str() {
            "2.5.4.3" => Some(RelativeDistinguishedName::CommonName(value)),
            "2.5.4.6" => Some(RelativeDistinguishedName::Country(value)),
            "2.5.4.10" => Some(RelativeDistinguishedName::Organization(value)),
            "2.5.4.11" => Some(RelativeDistinguishedName::OrganizationalUnit(value)),
            s => {
                println!("object identifier {} not supported", s);
                None
            }
        }
    }
}

impl<'a> Display for RelativeDistinguishedName<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use RelativeDistinguishedName::*;
        match self {
            CommonName(cn) => write!(f, "CN={}", cn),
            Country(c) => write!(f, "C={}", c),
            Organization(o) => write!(f, "CN={}", o),
            OrganizationalUnit(ou) => write!(f, "CN={}", ou),
        }
    }
}
