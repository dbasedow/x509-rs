use crate::der::{ObjectIdentifier, Value, parse_der, BitString};
use crate::error::Error;
use crate::x509::RelativeDistinguishedName;

const KEY_USAGE_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 15]);
const BASIC_CONSTRAINTS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 19]);
const CRL_DISTRIBUTION_POINTS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 31]);

#[derive(Debug)]
pub enum ExtensionType<'a> {
    KeyUsage(KeyUsage<'a>),
    BasicConstraints(BasicConstraints<'a>),
    CrlDistributionPoints(CrlDistributionPoints<'a>),
    Unknown(&'a ObjectIdentifier<'a>, &'a [u8]),
}

impl<'a> ExtensionType<'a> {
    pub fn new(oid: &'a ObjectIdentifier, data: &'a [u8]) -> Result<ExtensionType<'a>, Error> {
        match oid {
            KEY_USAGE_OID => Ok(ExtensionType::KeyUsage(KeyUsage::new(data)?)),
            BASIC_CONSTRAINTS_OID => Ok(ExtensionType::BasicConstraints(BasicConstraints::new(data)?)),
            CRL_DISTRIBUTION_POINTS_OID => Ok(ExtensionType::CrlDistributionPoints(CrlDistributionPoints::new(data)?)),
            _ => Ok(ExtensionType::Unknown(oid, data)),
        }
    }
}

#[derive(Debug)]
pub struct KeyUsage<'a>(BitString<'a>);

impl<'a> KeyUsage<'a> {
    fn new(data: &'a [u8]) -> Result<KeyUsage<'a>, Error> {
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

#[derive(Debug)]
pub struct BasicConstraints<'a>(Vec<Value<'a>>);

impl<'a> BasicConstraints<'a> {
    fn new(data: &'a [u8]) -> Result<BasicConstraints<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(BasicConstraints(s));
        }

        Err(Error::ParseError)
    }

    pub fn is_ca(&self) -> Result<bool, Error> {
        if !self.0.is_empty() {
            if let Value::Boolean(ca) = &self.0[0] {
                return Ok(ca.to_bool());
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

#[derive(Debug)]
pub struct CrlDistributionPoints<'a>(Vec<Value<'a>>);

impl<'a> CrlDistributionPoints<'a> {
    fn new(data: &'a [u8]) -> Result<CrlDistributionPoints<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(CrlDistributionPoints(s));
        }

        Err(Error::X509Error)
    }

    pub fn distribution_points(&'a self) -> Result<Vec<DistributionPoint<'a>>, Error> {
        let mut points = Vec::with_capacity(self.0.len());
        for v in &self.0 {
            points.push(DistributionPoint::new(v)?);
        }
        Ok(points)
    }
}

#[derive(Debug, Default)]
pub struct DistributionPoint<'a> {
    name: Option<DistributionPointName<'a>>,
    //reasons
    crl_issuer: Option<GeneralName<'a>>,
}

impl<'a> DistributionPoint<'a> {
    fn new(value: &'a Value) -> Result<DistributionPoint<'a>, Error> {
        if let Value::Sequence(seq, _) = value {
            let mut distribution_point = DistributionPoint::default();
            for field in seq {
                if let Value::ContextSpecific(ctx, content) = field {
                    match ctx {
                        0 => distribution_point.name = Some(DistributionPointName::new(content)?),
                        2 => distribution_point.crl_issuer = Some(GeneralName::new(content)?),
                        c => unimplemented!("distribution point context {}", c),
                    }
                }
            }
            return Ok(distribution_point);
        }

        Err(Error::X509Error)
    }
}

#[derive(Debug)]
pub enum DistributionPointName<'a> {
    FullName(GeneralName<'a>)
}

impl<'a> DistributionPointName<'a> {
    fn new(value: &'a Value) -> Result<DistributionPointName<'a>, Error> {
        if let Value::ContextSpecific(ctx, content) = value {
            match ctx {
                0 => return Ok(DistributionPointName::FullName(GeneralName::new(content)?)),
                c => unimplemented!("DistributionPointName context {}", c),
            }
        }

        Err(Error::X509Error)
    }
}

#[derive(Debug)]
pub enum GeneralName<'a> {
    URI(String),
    DirectoryName(Vec<RelativeDistinguishedName<'a>>),
}

impl<'a> GeneralName<'a> {
    fn new(value: &'a Value) -> Result<GeneralName<'a>, Error> {
        if let Value::ContextSpecificRaw(ctx, content) = value {
            match ctx {
                6 => return Ok(GeneralName::URI(String::from_utf8(content.to_vec())?)),
                ctx => unimplemented!("GeneralName context {}", ctx),
            }
        }
        if let Value::ContextSpecific(ctx, content) = value {
            match (ctx, content.as_ref()) {
                (4, Value::Sequence(seq, _)) => {
                    let mut result: Vec<RelativeDistinguishedName> = Vec::with_capacity(seq.len());
                    for e in seq {
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
                    return Ok(GeneralName::DirectoryName(result));
                }
                (ctx, _) => unimplemented!("GeneralName context {}", ctx),
            }
        }

        Err(Error::X509Error)
    }
}
