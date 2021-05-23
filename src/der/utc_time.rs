use crate::error::{Error, ParseError};
use chrono::prelude::*;
use std::fmt::{self, Debug, Display, Formatter};

use super::{DataType, ascii_slice_to_u32, expect_type};

#[derive(PartialEq)]
pub struct UTCTime<'a>(&'a [u8]);

impl<'a> UTCTime<'a> {
    pub fn to_datetime(&self) -> Result<DateTime<FixedOffset>, Error> {
        let data = self.0;
        let year = ascii_slice_to_u32(&data[..2])?;
        let year = year + 2000;

        let month = ascii_slice_to_u32(&data[2..4])?;
        let day = ascii_slice_to_u32(&data[4..6])?;

        let hour = ascii_slice_to_u32(&data[6..8])?;
        let minute = ascii_slice_to_u32(&data[8..10])?;

        let second;
        if data.len() == 13 || data.len() == 17 {
            second = ascii_slice_to_u32(&data[10..12])?;
        } else {
            second = 0;
        }

        let utc_offset: i32;
        if data.len() == 17 {
            let hour_offset = ascii_slice_to_u32(&data[11..13])?;
            let minute_offset = ascii_slice_to_u32(&data[14..16])?;
            let factor = if data[10] == 0x2d {
                // '-'
                -1
            } else {
                1
            };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        } else if data.len() == 19 {
            let hour_offset = ascii_slice_to_u32(&data[13..15])?;
            let minute_offset = ascii_slice_to_u32(&data[16..18])?;
            let factor = if data[12] == 0x2d {
                // '-'
                -1
            } else {
                1
            };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        } else {
            utc_offset = 0;
        }

        let offset = FixedOffset::east(utc_offset);
        let dt = offset
            .ymd(year as i32, month, day)
            .and_hms(hour, minute, second);

        Ok(dt)
    }
}

impl<'a> Display for UTCTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(dt) = self.to_datetime() {
            write!(f, "{}", dt.to_rfc3339())
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for UTCTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

pub fn expect_utc_time(data: &[u8]) -> Result<(&[u8], UTCTime), ParseError> {
    let (rest, value) = expect_type(data, DataType::UTCTime)?;

    Ok((rest, UTCTime(value)))
}
