use crate::{
    certificate::{AlgorithmIdentifier, Name, SubjectPublicKeyInfo, Validity, Version},
    der::{DataType, Integer, ToDer},
    error::EncodingError,
};

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct TBSCertificate {
    serial_number: Integer,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
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
    let mut issuer_dn = crate::certificate::DistinguishedName::default();
    let mut rdn_cn = crate::certificate::RelativeDistinguishedName::default();
    rdn_cn.insert(crate::certificate::AttributeTypeAndValue::new(
        crate::der::ObjectIdentifier::from_str("3.4.5").unwrap(),
        Box::new(crate::der::Utf8String::from_str("foo")),
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
    let mut subject_dn = crate::certificate::DistinguishedName::default();
    let mut rdn_cn = crate::certificate::RelativeDistinguishedName::default();
    rdn_cn.insert(crate::certificate::AttributeTypeAndValue::new(
        crate::der::ObjectIdentifier::from_str("3.4.5").unwrap(),
        Box::new(crate::der::Utf8String::from_str("bar")),
    ));
    subject_dn.push(rdn_cn);

    //SUBJECT PUBLIC KEY INFO
    let algo_id_rsa = crate::der::ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap();
    let algorithm_identifier_subject_key =
        AlgorithmIdentifier::new(algo_id_rsa, Box::new(crate::der::Null()));
    let public_key = crate::der::BitString::new(vec![20; 256], 2048);
    let sub_pub_key_info = SubjectPublicKeyInfo::new(algorithm_identifier_subject_key, public_key);

    let tbs = builder
        .serial_number(Integer::from_i64(10))
        .signature(AlgorithmIdentifier::new(
            crate::der::ObjectIdentifier::from_str("1.2.3").unwrap(),
            Box::new(crate::der::Null()),
        ))
        .issuer(Name::DistinguishedName(issuer_dn))
        .validity(validity)
        .subject(Name::DistinguishedName(subject_dn))
        .subject_public_key_info(sub_pub_key_info)
        .build()
        .unwrap();
    let tbs_bytes = tbs.to_der().unwrap();

    let res = crate::cert_parsing::expect_tbs(&tbs_bytes);
    let res = res.unwrap();
}
