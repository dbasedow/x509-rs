use crate::parse::error::ParseError;

pub struct ExplicitTag(u8);

impl ExplicitTag {
    pub fn try_new(tag: u8) -> Result<Self, ParseError> {
        // make sure the 3 high bits are not set, those are needed for tag class and P/C flag
        if tag < 0x1f {
            Ok(Self(tag))
        } else {
            Err(ParseError::UnsupportedTag(tag))
        }
    }

    pub fn get_identifier_octet(&self) -> u8 {
        0xa0 | self.0
    }
}