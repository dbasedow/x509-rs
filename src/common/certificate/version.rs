use std::convert::TryFrom;

#[derive(Debug, Eq, PartialEq)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl TryFrom<i64> for Version {
    type Error = crate::parse::error::ParseError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            _ => Err(crate::parse::error::ParseError::InvalidVersion),
        }
    }
}

impl From<&Version> for i64 {
    fn from(v: &Version) -> Self {
        match v {
            Version::V1 => 0,
            Version::V2 => 1,
            Version::V3 => 2,
        }
    }
}
