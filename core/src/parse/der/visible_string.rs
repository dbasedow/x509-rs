use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct VisibleStringRef<'a>(&'a [u8]);

impl<'a> Display for VisibleStringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let s = String::from_utf8_lossy(self.0);
        write!(f, "{}", s)
    }
}

impl<'a> Debug for VisibleStringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}
