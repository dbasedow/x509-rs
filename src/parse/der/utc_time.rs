use super::super::error::ParseError;
use super::{ascii_slice_to_u32, expect_type, DataType};
use crate::error::Error;
use chrono::prelude::*;
use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct UTCTimeRef<'a>(&'a [u8]);

impl<'a> UTCTimeRef<'a> {
    pub fn to_datetime(&self) -> Result<DateTime<Utc>, Error> {
        let data = self.0;
        let year = ascii_slice_to_u32(&data[..2])?;
        // the two digits represent dates from 1950 to 2050
        let year = if year > 50 { year + 1900 } else { year + 2000 };

        let month = ascii_slice_to_u32(&data[2..4])?;
        let day = ascii_slice_to_u32(&data[4..6])?;

        let hour = ascii_slice_to_u32(&data[6..8])?;
        let minute = ascii_slice_to_u32(&data[8..10])?;

        let mut data = &data[10..];
        let second;
        if data.len() == 3 || data.len() == 7 {
            second = ascii_slice_to_u32(&data[0..2])?;
            data = &data[2..];
        } else {
            second = 0;
        }

        let utc_offset: i32;
        if data[0] == 0x5a {
            // 'Z'
            utc_offset = 0;
        } else {
            assert!(data.len() == 5);
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
            .and_hms(hour, minute, second);

        Ok(dt.with_timezone(&Utc))
    }
}

impl<'a> Display for UTCTimeRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(dt) = self.to_datetime() {
            write!(f, "{}", dt.to_rfc3339())
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for UTCTimeRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}

pub fn expect_utc_time(data: &[u8]) -> Result<(&[u8], UTCTimeRef), ParseError> {
    let (rest, value) = expect_type(data, DataType::UTCTime)?;

    Ok((rest, UTCTimeRef(value)))
}

#[test]
fn test_utc_time_parsing_no_secs_zulu() {
    //YYMMDDhhmmZ
    let ref_dt = Utc.ymd(2021, 7, 31).and_hms(16, 44, 00);
    let d = ref_dt.format("%y%m%d%H%MZ").to_string();
    let utc = UTCTimeRef(&d.as_bytes());
    let res = utc.to_datetime();
    assert_eq!(res.unwrap(), ref_dt);
}

#[test]
fn test_utc_time_parsing_no_secs_pos_tz_offset() {
    // YYMMDDhhmm+hh'mm'
    let offset = FixedOffset::east(3600);
    let ref_dt_no_secs = offset.ymd(2021, 7, 31).and_hms(16, 44, 00);
    let d = ref_dt_no_secs.format("%y%m%d%H%M%z").to_string();
    let utc = UTCTimeRef(&d.as_bytes());
    let res = utc.to_datetime().unwrap();
    assert_eq!(res, ref_dt_no_secs);
}

#[test]
fn test_utc_time_parsing_no_secs_neg_tz_offset() {
    // YYMMDDhhmm-hh'mm'
    let offset = FixedOffset::west(3600);
    let ref_dt_no_secs = offset.ymd(2021, 7, 31).and_hms(16, 44, 00);
    let d = ref_dt_no_secs.format("%y%m%d%H%M%z").to_string();
    let utc = UTCTimeRef(&d.as_bytes());
    let res = utc.to_datetime().unwrap();
    assert_eq!(res, ref_dt_no_secs);
}

#[test]
fn test_utc_time_parsing_with_secs_zulu() {
    // YYMMDDhhmmssZ
    let ref_dt = Utc.ymd(2021, 7, 31).and_hms(16, 44, 40);
    let d = ref_dt.format("%y%m%d%H%M%SZ").to_string();
    let utc = UTCTimeRef(&d.as_bytes());
    let res = utc.to_datetime();
    assert_eq!(res.unwrap(), ref_dt);
}

#[test]
fn test_utc_time_parsing_with_secs_pos_tz_offset() {
    // YYMMDDhhmmss+hh'mm'
    let offset = FixedOffset::east(3600);
    let ref_dt_no_secs = offset.ymd(2021, 7, 31).and_hms(16, 44, 00);
    let d = ref_dt_no_secs.format("%y%m%d%H%M%S%z").to_string();
    let utc = UTCTimeRef(&d.as_bytes());
    let res = utc.to_datetime().unwrap();
    assert_eq!(res, ref_dt_no_secs);
}

#[test]
fn test_utc_time_parsing_with_secs_neg_tz_offset() {
    // YYMMDDhhmmss-hh'mm'
    let offset = FixedOffset::west(3600);
    let ref_dt_no_secs = offset.ymd(2021, 7, 31).and_hms(16, 44, 00);
    let d = ref_dt_no_secs.format("%y%m%d%H%M%S%z").to_string();
    let utc = UTCTimeRef(&d.as_bytes());
    let res = utc.to_datetime().unwrap();
    assert_eq!(res, ref_dt_no_secs);
}
