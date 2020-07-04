use crate::der::{ObjectIdentifier, Value};
use crate::error::Error;
use crate::extensions::ExtensionType;
use chrono::{DateTime, FixedOffset};
use ring::signature::VerificationAlgorithm;
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug, Display, Formatter};
use std::ops::Deref;
use untrusted::Input;

const COMMON_NAME_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 3]);
const SURNAME_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 4]);
const SERIAL_NUMBER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 5]);
const COUNTRY_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 6]);
const LOCALITY_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 7]);
const STATE_OR_PROVINCE_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 8]);
const STREET_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 9]);
const ORGANIZATION_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 10]);
const ORGANIZATIONAL_UNIT_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 11]);
const DESCRIPTION_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 13]);
const BUSINESS_CATEGORY_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 15]);
const POSTAL_ADDRESS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 16]);
const POSTAL_CODE_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 17]);
const POST_OFFICE_BOX_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 18]);
const TELEPHONE_NUMBER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 20]);
const INITIALS_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 43]);
const HOUSE_IDENTIFIER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 51]);
const ORGANIZATION_IDENTIFIER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 4, 97]);

const DUNS_BUSINESS_ID_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[43, 6, 1, 4, 1, 132, 7, 1]);
const LEGAL_ENTITY_ID_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[43, 6, 1, 4, 1, 131, 152, 42, 1]);
const SUBJECT_ALTERNATIVE_NAME_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[85, 29, 17]);
const UNSTRUCTURED_NAME_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 134, 247, 13, 1, 9, 2]);
const EMAIL_ADDRESS_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 134, 247, 13, 1, 9, 1]);
const JURISDICTION_OF_INCORPORATION_COUNTRY_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[43, 6, 1, 4, 1, 130, 55, 60, 2, 1, 3]);
const JURISDICTION_OF_INCORPORATION_STATE_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[43, 6, 1, 4, 1, 130, 55, 60, 2, 1, 2]);
const JURISDICTION_OF_INCORPORATION_LOCALITY_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[43, 6, 1, 4, 1, 130, 55, 60, 2, 1, 1]);
const DOMAIN_COMPONENT_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[9, 146, 38, 137, 147, 242, 44, 100, 1, 25]);

const SHA1_WITH_RSA_OBSOLETE_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[43, 14, 3, 2, 29]);
const SHA1_WITH_RSA_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 134, 247, 13, 1, 1, 5]);
const SHA256_WITH_RSA_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);
const SHA384_WITH_RSA_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 134, 247, 13, 1, 1, 12]);
const SHA512_WITH_RSA_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 134, 247, 13, 1, 1, 13]);
const ECDSA_WITH_SHA256_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 206, 61, 4, 3, 2]);
const ECDSA_WITH_SHA384_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 206, 61, 4, 3, 3]);
const ECDSA_WITH_SHA512_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 206, 61, 4, 3, 4]);
const DSA_WITH_SHA256_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[96, 134, 72, 1, 101, 3, 4, 3, 2]);
const RSA_WITH_MD5_OID: &ObjectIdentifier<'static> =
    &ObjectIdentifier(&[42, 134, 72, 134, 247, 13, 1, 1, 4]);

/// A parsed X.509 certificate
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

#[derive(Debug)]
pub enum SignatureAlgorithm {
    Sha1Rsa,
    Sha256Rsa,
    Sha384Rsa,
    Sha512Rsa,
    Sha256Ecdsa,
    Sha384Ecdsa,
    Sha512Ecdsa,
    Sha256Dsa,
    Md5Rsa,
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

#[derive(Debug)]
enum Part {
    SerialNumber,
    Signature,
    Issuer,
    Validity,
    Subject,
    SubjectPublicKeyInfo,
    IssuerUniqueID,
    SubjectUniqueID,
    Extensions,
}

impl<'a> Certificate<'a> {
    fn index_for(&self, part: Part) -> Result<usize, Error> {
        use Part::*;

        let version = self.version_no_default()?;
        let has_explicit_version = version.is_some();
        match (part, has_explicit_version) {
            (SerialNumber, false) => Ok(0),
            (SerialNumber, true) => Ok(1),
            (Signature, false) => Ok(1),
            (Signature, true) => Ok(2),
            (Issuer, false) => Ok(2),
            (Issuer, true) => Ok(3),
            (Validity, false) => Ok(3),
            (Validity, true) => Ok(4),
            (Subject, false) => Ok(4),
            (Subject, true) => Ok(5),
            (SubjectPublicKeyInfo, false) => Ok(5),
            (SubjectPublicKeyInfo, true) => Ok(6),
            (Extensions, _) => Ok(self.tbs_cert()?.len() - 1),
            (p, v) => unimplemented!("not implemented: ({:?}, {})", p, v),
        }
    }

    /// Create a new instance from parsed DER
    pub fn from_value(value: Value<'a>) -> Certificate<'a> {
        Certificate(value)
    }

    pub fn serial(&self) -> Result<num_bigint::BigInt, Error> {
        let tbs_cert = self.tbs_cert()?;
        let index = self.index_for(Part::SerialNumber)?;
        if let Value::Integer(serial) = &tbs_cert[index] {
            return Ok(serial.to_big_int());
        }
        Err(Error::X509Error)
    }

    /// Which version of X.509 is used
    pub fn version(&self) -> Result<Version, Error> {
        match self.version_no_default()? {
            Some(v) => Ok(v),
            None => Ok(Version::V1),
        }
    }

    fn version_no_default(&self) -> Result<Option<Version>, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::ContextSpecific(_, version) = &tbs_cert[0] {
            if let Value::Integer(version) = version.deref() {
                return Ok(Some(version.to_i64().try_into()?));
            }
        }
        Ok(None)
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
        let index = self.index_for(Part::Validity)?;
        if let Value::Sequence(validty, _) = &tbs_cert[index] {
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
        let index = self.index_for(Part::Validity)?;
        if let Value::Sequence(validty, _) = &tbs_cert[index] {
            return match &validty[1] {
                Value::UTCTime(dt) => dt.to_datetime(),
                Value::GeneralizedTime(dt) => dt.to_datetime(),
                _ => unimplemented!("validity must be either UTC or Generalized Time"),
            };
        }
        Err(Error::X509Error)
    }

    /// Issuer of the certificate. Returns a number of relative distinguished names
    pub fn issuer(&self) -> Result<Vec<RelativeDistinguishedName>, Error> {
        let index = self.index_for(Part::Issuer)?;
        self.get_rdns_at_offset(index)
    }

    /// Subject of the certificate. Returns a number of relative distinguished names
    pub fn subject(&self) -> Result<Vec<RelativeDistinguishedName>, Error> {
        let index = self.index_for(Part::Subject)?;
        self.get_rdns_at_offset(index)
    }

    fn get_rdns_at_offset(&self, offset: usize) -> Result<Vec<RelativeDistinguishedName>, Error> {
        let tbs_cert = self.tbs_cert()?;
        if let Value::Sequence(entries, _) = &tbs_cert[offset] {
            let mut result: Vec<RelativeDistinguishedName> = Vec::with_capacity(entries.len());
            for e in entries {
                if let Value::Set(s) = e {
                    if let Value::Sequence(sub, _) = &s[0] {
                        if let Value::ObjectIdentifier(oid) = &sub[0] {
                            if let Some(rdn) =
                                RelativeDistinguishedName::from_oid_and_string(&oid, &sub[1])
                            {
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

    /// Returns the data used in the signature calculation. (TBS = to be signed)
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
        let index = self.index_for(Part::SubjectPublicKeyInfo)?;
        if let Value::Sequence(seq, _) = &tbs_cert[index] {
            if let Value::BitString(key) = &seq[1] {
                let (_, data) = key.data();
                return Ok(data);
            }
        }

        Err(Error::X509Error)
    }

    /// The signature algorithm is stored in the signed and unsigned part of the certificate. Both MUST match!
    pub fn signature_algorithm_unsigned(&self) -> Result<SignatureAlgorithm, Error> {
        if let Value::Sequence(certificate, _) = &self.0 {
            if let Value::Sequence(algorithm_identifier, _) = &certificate[1] {
                if let Value::ObjectIdentifier(oid) = &algorithm_identifier[0] {
                    return Ok(lookup_algorithm_identifier(oid));
                }
            }
        }
        Err(Error::X509Error)
    }

    /// The signature algorithm is stored in the signed and unsigned part of the certificate. Both MUST match!
    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm, Error> {
        let tbs_cert = self.tbs_cert()?;
        let index = self.index_for(Part::Signature)?;
        if let Value::Sequence(algorithm_identifier, _) = &tbs_cert[index] {
            if algorithm_identifier.len() > 1 {
                if Value::Null != algorithm_identifier[1] {
                    unimplemented!("algorithm params: {:x?}", algorithm_identifier[1]);
                }
            }
            if let Value::ObjectIdentifier(oid) = &algorithm_identifier[0] {
                return Ok(lookup_algorithm_identifier(oid));
            }
        }
        Err(Error::X509Error)
    }

    pub fn extensions(&self) -> Result<Option<Vec<Extension>>, Error> {
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
                                        let extension = Extension(
                                            oid.clone(),
                                            critical.to_bool(),
                                            data.clone(),
                                        );
                                        res.push(extension);
                                    }
                                } else {
                                    let critical = false;
                                    if let Value::OctetString(data) = &ext[1] {
                                        let extension =
                                            Extension(oid.clone(), critical, data.clone());
                                        res.push(extension);
                                    }
                                }
                            }
                        }
                    }
                    return Ok(Some(res));
                }
            }
        }
        Ok(None)
    }

    pub fn self_signed(&self) -> Result<bool, Error> {
        let subject = self.subject()?;
        let issuer = self.issuer()?;
        if subject.len() == issuer.len() {
            for i in 0..subject.len() {
                if subject[i] != issuer[i] {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        let alg: &dyn VerificationAlgorithm = match self.signature_algorithm()? {
            SignatureAlgorithm::Sha1Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA1,
            SignatureAlgorithm::Sha256Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::Sha384Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            SignatureAlgorithm::Sha512Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            SignatureAlgorithm::Sha256Ecdsa => &ring::signature::ECDSA_P256_SHA256_ASN1,
            SignatureAlgorithm::Sha384Ecdsa => &ring::signature::ECDSA_P384_SHA384_FIXED,
            _ => return Err(Error::X509Error),
        };

        ring::signature::verify(
            alg,
            Input::from(self.public_key()?),
            Input::from(msg),
            Input::from(signature),
        )
        .map_err(|_| Error::InvalidSignature)
    }
}

fn lookup_algorithm_identifier(oid: &ObjectIdentifier) -> SignatureAlgorithm {
    match oid {
        SHA1_WITH_RSA_OID => SignatureAlgorithm::Sha1Rsa,
        SHA1_WITH_RSA_OBSOLETE_OID => SignatureAlgorithm::Sha1Rsa,
        SHA256_WITH_RSA_OID => SignatureAlgorithm::Sha256Rsa,
        SHA384_WITH_RSA_OID => SignatureAlgorithm::Sha384Rsa,
        SHA512_WITH_RSA_OID => SignatureAlgorithm::Sha512Rsa,
        ECDSA_WITH_SHA256_OID => SignatureAlgorithm::Sha256Ecdsa,
        ECDSA_WITH_SHA384_OID => SignatureAlgorithm::Sha384Ecdsa,
        ECDSA_WITH_SHA512_OID => SignatureAlgorithm::Sha512Ecdsa,
        DSA_WITH_SHA256_OID => SignatureAlgorithm::Sha256Dsa,
        RSA_WITH_MD5_OID => SignatureAlgorithm::Md5Rsa,
        o => unimplemented!("unknown oid: {}, ({:?})", o, o.0),
    }
}

pub struct Extension<'a>(ObjectIdentifier<'a>, bool, &'a [u8]);

impl<'a> Debug for Extension<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "Extension: {} critical: {} data: {:x?}",
            self.0, self.1, self.2
        )
    }
}

impl<'a> Extension<'a> {
    pub fn object_identifier(&self) -> &ObjectIdentifier<'a> {
        &self.0
    }

    pub fn critical(&self) -> bool {
        self.1
    }

    pub fn data_raw(&self) -> &[u8] {
        self.2
    }

    pub fn data(&self) -> Result<ExtensionType, Error> {
        ExtensionType::new(&self.0, self.2)
    }
}

#[derive(Debug, PartialEq)]
pub enum RelativeDistinguishedName<'a> {
    CommonName(&'a Value<'a>),
    Surname(&'a Value<'a>),
    SerialNumber(&'a Value<'a>),
    Country(&'a Value<'a>),
    StateOrProvince(&'a Value<'a>),
    Street(&'a Value<'a>),
    Locality(&'a Value<'a>),
    Organization(&'a Value<'a>),
    OrganizationalUnit(&'a Value<'a>),
    Description(&'a Value<'a>),
    BusinessCategory(&'a Value<'a>),
    PostalAddress(&'a Value<'a>),
    PostalCode(&'a Value<'a>),
    PostOfficeBox(&'a Value<'a>),
    TelephoneNumber(&'a Value<'a>),
    Initials(&'a Value<'a>),
    HouseIdentifier(&'a Value<'a>),
    OrganizationIdentifier(&'a Value<'a>),

    DunsBusinessId(&'a Value<'a>),
    LegalEntityId(&'a Value<'a>),
    SubjectAlternativeName(&'a Value<'a>),
    UnstructuredName(&'a Value<'a>),
    EmailAddress(&'a Value<'a>),
    JurisdictionOfIncorporationCountry(&'a Value<'a>),
    JurisdictionOfIncorporationState(&'a Value<'a>),
    JurisdictionOfIncorporationLocality(&'a Value<'a>),
    DomainComponent(&'a Value<'a>),
}

impl<'a> RelativeDistinguishedName<'a> {
    pub fn from_oid_and_string(
        oid: &ObjectIdentifier,
        value: &'a Value,
    ) -> Option<RelativeDistinguishedName<'a>> {
        match oid {
            COMMON_NAME_OID => Some(RelativeDistinguishedName::CommonName(value)),
            SURNAME_OID => Some(RelativeDistinguishedName::Surname(value)),
            SERIAL_NUMBER_OID => Some(RelativeDistinguishedName::SerialNumber(value)),
            COUNTRY_OID => Some(RelativeDistinguishedName::Country(value)),
            STATE_OR_PROVINCE_OID => Some(RelativeDistinguishedName::StateOrProvince(value)),
            STREET_OID => Some(RelativeDistinguishedName::Street(value)),
            LOCALITY_OID => Some(RelativeDistinguishedName::Locality(value)),
            ORGANIZATION_OID => Some(RelativeDistinguishedName::Organization(value)),
            ORGANIZATIONAL_UNIT_OID => Some(RelativeDistinguishedName::OrganizationalUnit(value)),
            DESCRIPTION_OID => Some(RelativeDistinguishedName::Description(value)),
            BUSINESS_CATEGORY_OID => Some(RelativeDistinguishedName::BusinessCategory(value)),
            POSTAL_ADDRESS_OID => Some(RelativeDistinguishedName::PostalAddress(value)),
            POSTAL_CODE_OID => Some(RelativeDistinguishedName::PostalCode(value)),
            POST_OFFICE_BOX_OID => Some(RelativeDistinguishedName::PostOfficeBox(value)),
            TELEPHONE_NUMBER_OID => Some(RelativeDistinguishedName::TelephoneNumber(value)),
            INITIALS_OID => Some(RelativeDistinguishedName::Initials(value)),
            HOUSE_IDENTIFIER_OID => Some(RelativeDistinguishedName::HouseIdentifier(value)),
            ORGANIZATION_IDENTIFIER_OID => {
                Some(RelativeDistinguishedName::OrganizationIdentifier(value))
            }

            DUNS_BUSINESS_ID_OID => Some(RelativeDistinguishedName::DunsBusinessId(value)),
            LEGAL_ENTITY_ID_OID => Some(RelativeDistinguishedName::LegalEntityId(value)),
            SUBJECT_ALTERNATIVE_NAME_OID => {
                Some(RelativeDistinguishedName::SubjectAlternativeName(value))
            }
            UNSTRUCTURED_NAME_OID => Some(RelativeDistinguishedName::UnstructuredName(value)),
            EMAIL_ADDRESS_OID => Some(RelativeDistinguishedName::EmailAddress(value)),
            JURISDICTION_OF_INCORPORATION_COUNTRY_OID => {
                Some(RelativeDistinguishedName::JurisdictionOfIncorporationCountry(value))
            }
            JURISDICTION_OF_INCORPORATION_STATE_OID => Some(
                RelativeDistinguishedName::JurisdictionOfIncorporationState(value),
            ),
            JURISDICTION_OF_INCORPORATION_LOCALITY_OID => {
                Some(RelativeDistinguishedName::JurisdictionOfIncorporationLocality(value))
            }
            DOMAIN_COMPONENT_OID => Some(RelativeDistinguishedName::DomainComponent(value)),
            s => {
                eprintln!("object identifier {} not supported ({:?})", s, s.0);
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
            Surname(cn) => write!(f, "SN={}", cn),
            SerialNumber(sn) => write!(f, "serial-number={}", sn),
            Country(c) => write!(f, "C={}", c),
            StateOrProvince(s) => write!(f, "S={}", s),
            Street(s) => write!(f, "street={}", s),
            Locality(l) => write!(f, "L={}", l),
            Organization(o) => write!(f, "O={}", o),
            OrganizationalUnit(ou) => write!(f, "OU={}", ou),
            Description(d) => write!(f, "description={}", d),
            BusinessCategory(bc) => write!(f, "business-category={}", bc),
            PostalAddress(pa) => write!(f, "postal-address={}", pa),
            PostalCode(pc) => write!(f, "postal-code={}", pc),
            PostOfficeBox(pob) => write!(f, "po-box={}", pob),
            TelephoneNumber(tn) => write!(f, "phone={}", tn),
            Initials(i) => write!(f, "initials={}", i),
            HouseIdentifier(h) => write!(f, "house-id={}", h),
            OrganizationIdentifier(id) => write!(f, "org-id={}", id),

            DunsBusinessId(e) => write!(f, "DUNS-id={}", e),
            LegalEntityId(e) => write!(f, "LEI-id={}", e),
            SubjectAlternativeName(e) => write!(f, "SAN={}", e),
            UnstructuredName(e) => write!(f, "unstructured-name={}", e),
            EmailAddress(e) => write!(f, "email={}", e),
            JurisdictionOfIncorporationCountry(c) => write!(f, "jurisdiction-of-inc-country={}", c),
            JurisdictionOfIncorporationState(c) => write!(f, "jurisdiction-of-inc-state={}", c),
            JurisdictionOfIncorporationLocality(c) => {
                write!(f, "jurisdiction-of-inc-locality={}", c)
            }
            DomainComponent(dc) => write!(f, "DC={}", dc),
        }
    }
}
