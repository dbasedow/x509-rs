use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct T61String<'a>(&'a [u8]);

impl<'a> Display for T61String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", String::from_utf8_lossy(self.0))
    }
}

impl<'a> Debug for T61String<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}
