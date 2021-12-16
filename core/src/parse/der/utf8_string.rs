use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq, Eq, Hash)]
pub struct Utf8StringRef<'a>(pub(crate) &'a [u8]);

impl<'a> Display for Utf8StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for Utf8StringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}
