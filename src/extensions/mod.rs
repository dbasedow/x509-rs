use crate::der::{ObjectIdentifier, Value, parse_der, BitString};
use crate::error::Error;
use crate::x509::RelativeDistinguishedName;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::extensions::GeneralName::Unsupported;
use crate::utils::u8_slice_to_16_vec;
use num_bigint::BigInt;
use crate::extensions::key_usage::KeyUsage;
use crate::extensions::basic_constraints::BasicConstraints;
use crate::extensions::crl_distribution_points::CrlDistributionPoints;
use crate::extensions::subject_alternative_names::SubjectAlternativeNames;
use crate::extensions::authority_info_access::AuthorityInfoAccess;
use crate::extensions::authority_key_identifier::AuthorityKeyIdentifier;
use crate::extensions::subject_key_identifier::SubjectKeyIdentifier;

const SUBJECT_KEY_IDENTIFIER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 14]);
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
    SubjectKeyIdentifier(SubjectKeyIdentifier<'a>),
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
            SUBJECT_KEY_IDENTIFIER_OID => Ok(ExtensionType::SubjectKeyIdentifier(SubjectKeyIdentifier::new(data)?)),
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


mod key_usage;
mod basic_constraints;
mod crl_distribution_points;
mod subject_alternative_names;
mod authority_info_access;
mod authority_key_identifier;
mod subject_key_identifier;
