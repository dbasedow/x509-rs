use crate::Value;
use crate::Error;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;
use chrono::{DateTime, FixedOffset};

pub struct Certificate<'a>(Value<'a>);

pub enum Version {
    V1,
    V2,
    V3,
}

pub enum SignatureAlgorithm {
    PKCS1_SHA256_RSA,
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

    pub fn serial(&self) -> Result<i64, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::Integer(serial) = &tbs_cert[1] {
            return Ok(serial.to_i64());
        }
        Err(Error::X509Error)
    }

    pub fn version(&self) -> Result<Version, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::ContextSpecific(ctx, version) = &tbs_cert[0] {
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
                        "1.2.840.113549.1.1.11" => return Ok(SignatureAlgorithm::PKCS1_SHA256_RSA),
                        _ => return Err(Error::X509Error),
                    }
                }
            }
        }
        Err(Error::X509Error)
    }
}
