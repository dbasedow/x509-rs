use super::super::{
    der::{expect_integer, try_get_explicit, ExplicitTag},
    error::ParseError,
};
use super::expect_empty;
use crate::common::certificate::Version;
use std::convert::TryFrom;

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
