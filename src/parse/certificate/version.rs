use super::super::{
    der::{expect_integer, try_get_explicit, ExplicitTag},
    error::ParseError,
};
use super::expect_empty;
use std::convert::TryFrom;

#[derive(Debug, Eq, PartialEq)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl TryFrom<i64> for Version {
    type Error = ParseError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            _ => Err(ParseError::InvalidVersion),
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

pub fn parse_version(data: &[u8]) -> Result<(&[u8], Version), ParseError> {
    match try_get_explicit(data, ExplicitTag::try_new(0)?) {
        Ok((rest, inner)) => {
            let (inner, version) = expect_integer(inner)?;
            // the version integer should take up all the space in the buffer
            expect_empty(inner)?;
            Ok((rest, Version::try_from(version.to_i64()?)?))
        }
        _ => Ok((data, Version::V1)),
    }
}
