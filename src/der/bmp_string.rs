use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct BMPString<'a>(&'a [u8]);

impl<'a> Display for BMPString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let u16s: Vec<u16> = self
            .0
            .chunks(2)
            .map(|a| u16::from_be_bytes([a[0], a[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&u16s) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for BMPString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}
