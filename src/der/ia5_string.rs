use crate::error::{Error, ParseError};
use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct IA5String<'a>(&'a [u8]);

impl<'a> IA5String<'a> {
    pub fn to_string(&self) -> Result<String, Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            return Ok(s);
        }
        Err(Error::ParseError(ParseError::StringEncoding))
    }
}

impl<'a> Display for IA5String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for IA5String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}
