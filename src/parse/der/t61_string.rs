use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct T61StringRef<'a>(&'a [u8]);

impl<'a> Display for T61StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", String::from_utf8_lossy(self.0))
    }
}

impl<'a> Debug for T61StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}
