use super::{
    certificate::{AlgorithmIdentifier, Extensions, Name, SubjectPublicKeyInfo, Validity},
    der::{wrap_in_explicit_tag, DataType, Integer, ToDer},
    error::EncodingError,
};
use crate::common::{certificate::Version, der::ExplicitTag};

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct TBSCertificate {
    serial_number: Integer,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    extensions: Option<Extensions>,
}

impl ToDer for TBSCertificate {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&Version::V3.to_der()?);
        tbs.extend_from_slice(&self.serial_number.to_der()?);
        tbs.extend_from_slice(&self.signature.to_der()?);
        tbs.extend_from_slice(&self.issuer.to_der()?);
        tbs.extend_from_slice(&self.validity.to_der()?);
        tbs.extend_from_slice(&self.subject.to_der()?);
        tbs.extend_from_slice(&self.subject_public_key_info.to_der()?);
        if let Some(extensions) = &self.extensions {
            assert!(extensions.len() >= 1);
            let extensions_der = extensions.to_der()?;
            tbs.extend_from_slice(&wrap_in_explicit_tag(
                &extensions_der,
                ExplicitTag::try_new(3).unwrap(),
            ));
        }

        Ok(tbs)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}

#[test]
fn test_tbs_cert_builder() {
    let builder = TBSCertificateBuilder::default();
    //ISSUER
    let mut issuer_dn = super::certificate::DistinguishedName::default();
    let mut rdn_cn = super::certificate::RelativeDistinguishedName::default();
    rdn_cn.insert(super::certificate::AttributeTypeAndValue::new(
        super::der::ObjectIdentifier::from_str("3.4.5").unwrap(),
        Box::new(super::der::Utf8String::from_str("foo")),
    ));
    issuer_dn.push(rdn_cn);

    //VALIDITY
    let not_before = chrono::DateTime::parse_from_rfc3339("2021-07-31T12:33:53-00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let not_after = chrono::DateTime::parse_from_rfc3339("2022-07-31T12:33:53-00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let validity = Validity::new(not_before, not_after);

    //SUBJECT
    let mut subject_dn = super::certificate::DistinguishedName::default();
    let mut rdn_cn = super::certificate::RelativeDistinguishedName::default();
    rdn_cn.insert(super::certificate::AttributeTypeAndValue::new(
        super::der::ObjectIdentifier::from_str("3.4.5").unwrap(),
        Box::new(super::der::Utf8String::from_str("bar")),
    ));
    subject_dn.push(rdn_cn);

    //SUBJECT PUBLIC KEY INFO
    let algo_id_rsa = super::der::ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap();
    let algorithm_identifier_subject_key =
        AlgorithmIdentifier::new(algo_id_rsa, Box::new(super::der::Null()));
    let public_key = super::der::BitString::new(vec![20; 256], 2048);
    let sub_pub_key_info = SubjectPublicKeyInfo::new(algorithm_identifier_subject_key, public_key);

    //EXTENSION
    let mut extensions = Extensions::default();
    let extension = super::certificate::Extension::new(
        super::der::ObjectIdentifier::from_str("3.8.7").unwrap(),
        false.into(),
        super::der::OctetString::new(vec![3; 2]),
    );
    extensions.add(extension);

    let tbs = builder
        .serial_number(Integer::from_i64(10))
        .signature(AlgorithmIdentifier::new(
            super::der::ObjectIdentifier::from_str("1.2.3").unwrap(),
            Box::new(super::der::Null()),
        ))
        .issuer(Name::DistinguishedName(issuer_dn))
        .validity(validity)
        .subject(Name::DistinguishedName(subject_dn))
        .subject_public_key_info(sub_pub_key_info)
        .extensions(Some(extensions))
        .build()
        .unwrap();
    let tbs_bytes = tbs.to_der().unwrap();

    let res = crate::parse::parsing::expect_tbs(&tbs_bytes);
    assert!(res.is_ok());
}
