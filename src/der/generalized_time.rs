use crate::error::{Error, ParseError};
use chrono::prelude::*;
use std::fmt::{self, Debug, Display, Formatter};

use super::{DataType, ascii_slice_to_u32, expect_type};

#[derive(PartialEq)]
pub struct GeneralizedTime<'a>(&'a [u8]);

impl<'a> GeneralizedTime<'a> {
    pub fn to_datetime(&self) -> Result<DateTime<FixedOffset>, Error> {
        let data = self.0;
        let year = ascii_slice_to_u32(&data[..4])?;

        let month = ascii_slice_to_u32(&data[4..6])?;
        let day = ascii_slice_to_u32(&data[6..8])?;

        let hour = ascii_slice_to_u32(&data[8..10])?;
        let minute = ascii_slice_to_u32(&data[10..12])?;
        let second = ascii_slice_to_u32(&data[12..14])?;

        let nanos: u32;
        if data[14] == 0x2e {
            // '.'
            // handle fractional seconds
            let mut fractional_len = 0;
            for (i, &ch) in (&data[15..]).iter().enumerate() {
                if ch > 0x39 || ch < 0x30 {
                    //end of fractional seconds
                    fractional_len = i;
                }
            }
            nanos = ascii_slice_to_u32(&data[15..15 + fractional_len])?;
        } else {
            nanos = 0;
        }

        let utc_offset: i32;
        if data[data.len() - 1] == 0x5a {
            // 'Z'
            utc_offset = 0;
        } else {
            let data = &data[data.len() - 6..];
            let hour_offset = ascii_slice_to_u32(&data[1..3])?;
            let minute_offset = ascii_slice_to_u32(&data[3..5])?;
            let factor = if data[0] == 0x2d {
                // '-'
                -1
            } else {
                1
            };

            utc_offset = factor * (hour_offset * 3600 + minute_offset * 60) as i32;
        }

        let offset = FixedOffset::east(utc_offset);
        let dt = offset
            .ymd(year as i32, month, day)
            .and_hms_nano(hour, minute, second, nanos);

        Ok(dt)
    }
}

impl<'a> Display for GeneralizedTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(dt) = self.to_datetime() {
            write!(f, "{}", dt.to_rfc3339())
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for GeneralizedTime<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

pub fn expect_generalized_time(data: &[u8]) -> Result<(&[u8], GeneralizedTime), ParseError> {
    let (rest, value) = expect_type(data, DataType::GeneralizedTime)?;

    Ok((rest, GeneralizedTime(value)))
}
