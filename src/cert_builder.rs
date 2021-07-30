use crate::{
    certificate::{AlgorithmIdentifier, Name, Version},
    der::{DataType, Integer, ToDer},
    error::EncodingError,
};

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct TBSCertificate {
    serial_number: Integer,
    signature: AlgorithmIdentifier,
    issuer: Name,
}

impl ToDer for TBSCertificate {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&Version::V3.to_der()?);
        tbs.extend_from_slice(&self.serial_number.to_der()?);
        tbs.extend_from_slice(&self.signature.to_der()?);
        tbs.extend_from_slice(&self.issuer.to_der()?);

        Ok(tbs)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.into()
    }
}

#[test]
fn test_tbs_cert_builder() {
    let builder = TBSCertificateBuilder::default();
    let mut issuer_dn = crate::certificate::DistinguishedName::default();
    let mut rdn_cn = crate::certificate::RelativeDistinguishedName::default();
    rdn_cn.insert(crate::certificate::AttributeTypeAndValue::new(
        crate::der::ObjectIdentifier::from_str("3.4.5").unwrap(),
        Box::new(crate::der::Utf8String::from_str("foo")),
    ));
    issuer_dn.push(rdn_cn);

    let tbs = builder
        .serial_number(Integer::from_i64(10))
        .signature(AlgorithmIdentifier::new(
            crate::der::ObjectIdentifier::from_str("1.2.3").unwrap(),
            Box::new(crate::der::Null()),
        ))
        .issuer(Name::DistinguishedName(issuer_dn))
        .build()
        .unwrap();
    let tbs_bytes = tbs.to_der().unwrap();
    assert_eq!(tbs_bytes, &[0x00]);
}
