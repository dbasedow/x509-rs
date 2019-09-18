use crate::der::{ObjectIdentifier, Value, parse_der, BitString};
use crate::error::Error;
use crate::x509::RelativeDistinguishedName;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::extensions::GeneralName::Unsupported;
use crate::utils::u8_slice_to_16_vec;
use num_bigint::BigInt;

const KEY_USAGE_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 15]);
const SUBJECT_ALTERNATIVE_NAME_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 17]);
const BASIC_CONSTRAINTS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 19]);
const CRL_DISTRIBUTION_POINTS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 31]);
const AUTHORITY_KEY_IDENTIFIER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 35]);
const AUTHORITY_INFO_ACCESS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 1, 1]);


const AUTHORITY_INFO_ACCESS_OCSP_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 48, 1]);
const AUTHORITY_INFO_ACCESS_CA_ISSUERS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 48, 2]);

#[derive(Debug)]
pub enum ExtensionType<'a> {
    KeyUsage(KeyUsage<'a>),
    SubjectAlternativeNames(SubjectAlternativeNames<'a>),
    BasicConstraints(BasicConstraints<'a>),
    CrlDistributionPoints(CrlDistributionPoints<'a>),
    AuthorityInfoAccess(AuthorityInfoAccess<'a>),
    AuthorityKeyIdentifier(AuthorityKeyIdentifier<'a>),
    Unknown(&'a ObjectIdentifier<'a>, &'a [u8]),
}

impl<'a> ExtensionType<'a> {
    pub fn new(oid: &'a ObjectIdentifier, data: &'a [u8]) -> Result<ExtensionType<'a>, Error> {
        match oid {
            KEY_USAGE_OID => Ok(ExtensionType::KeyUsage(KeyUsage::new(data)?)),
            SUBJECT_ALTERNATIVE_NAME_OID => Ok(ExtensionType::SubjectAlternativeNames(SubjectAlternativeNames::new(data)?)),
            BASIC_CONSTRAINTS_OID => Ok(ExtensionType::BasicConstraints(BasicConstraints::new(data)?)),
            CRL_DISTRIBUTION_POINTS_OID => Ok(ExtensionType::CrlDistributionPoints(CrlDistributionPoints::new(data)?)),
            AUTHORITY_KEY_IDENTIFIER_OID => Ok(ExtensionType::AuthorityKeyIdentifier(AuthorityKeyIdentifier::new(data)?)),
            AUTHORITY_INFO_ACCESS_OID => Ok(ExtensionType::AuthorityInfoAccess(AuthorityInfoAccess::new(data)?)),
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
    Rfc822Address(String),
    DnsName(String),
    URI(String),
    DirectoryName(Vec<RelativeDistinguishedName<'a>>),
    IpAddress(IpAddr),
    Unsupported,
}

impl<'a> GeneralName<'a> {
    fn new(value: &'a Value) -> Result<GeneralName<'a>, Error> {
        if let Value::ContextSpecificRaw(ctx, content) = value {
            match ctx {
                1 => return Ok(GeneralName::Rfc822Address(String::from_utf8(content.to_vec())?)),
                2 => return Ok(GeneralName::DnsName(String::from_utf8(content.to_vec())?)),
                6 => return Ok(GeneralName::URI(String::from_utf8(content.to_vec())?)),
                7 if content.len() == 4 => return Ok(GeneralName::IpAddress(IpAddr::V4(Ipv4Addr::new(content[0], content[1], content[2], content[3])))),
                7 if content.len() == 16 => {
                    let seg = u8_slice_to_16_vec(content);
                    let addr = Ipv6Addr::new(seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7]);
                    return Ok(GeneralName::IpAddress(IpAddr::V6(addr)));
                }
                ctx => unimplemented!("GeneralName context {}, {:x?}", ctx, content),
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
                (ctx, _) => {
                    eprintln!("unimplemented GeneralName context {}, {:?}", ctx, content);
                    return Ok(GeneralName::Unsupported);
                }
            }
        }

        Err(Error::X509Error)
    }
}

#[derive(Debug)]
pub struct SubjectAlternativeNames<'a>(Vec<Value<'a>>);

impl<'a> SubjectAlternativeNames<'a> {
    fn new(data: &'a [u8]) -> Result<SubjectAlternativeNames<'a>, Error> {
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

#[derive(Debug)]
pub struct AuthorityInfoAccess<'a>(Vec<Value<'a>>);

impl<'a> AuthorityInfoAccess<'a> {
    fn new(data: &'a [u8]) -> Result<AuthorityInfoAccess<'a>, Error> {
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

#[derive(Debug)]
pub struct AuthorityKeyIdentifier<'a>(Vec<Value<'a>>);

impl<'a> AuthorityKeyIdentifier<'a> {
    fn new(data: &'a [u8]) -> Result<AuthorityKeyIdentifier<'a>, Error> {
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
