use super::super::{
    der::{
        expect_generalized_time, expect_sequence, expect_utc_time, GeneralizedTimeRef, UTCTimeRef,
    },
    error::ParseError,
};
use super::expect_empty;

#[derive(Debug)]
enum TimeRef<'a> {
    UTCTimeRef(UTCTimeRef<'a>),
    GeneralizedTimeRef(GeneralizedTimeRef<'a>),
}

impl<'a> TimeRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        if let Ok((rest, utc)) = expect_utc_time(data) {
            return Ok((rest, Self::UTCTimeRef(utc)));
        }
        if let Ok((rest, generalized)) = expect_generalized_time(data) {
            return Ok((rest, Self::GeneralizedTimeRef(generalized)));
        }

        Err(ParseError::MalformedData)
    }
}

#[derive(Debug)]
pub struct ValidityRef<'a> {
    not_before: TimeRef<'a>,
    not_after: TimeRef<'a>,
}

impl<'a> ValidityRef<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, not_before) = TimeRef::parse(data)?;
        let (data, not_after) = TimeRef::parse(data)?;
        expect_empty(data)?;
        let validity = Self {
            not_after,
            not_before,
        };

        Ok((rest, validity))
    }
}
