use super::super::{
    der::{Integer, ToDer},
    error::EncodingError,
};
use crate::common::{certificate::Version, der::ExplicitTag};

impl ToDer for Version {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let v: i64 = self.into();

        let i = Integer::from_i64(v);
        i.to_der()
    }

    fn get_tag(&self) -> u8 {
        ExplicitTag::try_new(0).unwrap().get_identifier_octet()
    }
}

#[test]
fn test_encode_version() {
    let der = Version::V3.to_der();
    assert_eq!(der.unwrap(), &[0xa0, 0x03, 0x02, 0x01, 0x02]);
}
