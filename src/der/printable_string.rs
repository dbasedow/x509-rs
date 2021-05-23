use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct PrintableString<'a>(&'a [u8]);

impl<'a> Display for PrintableString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for PrintableString<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self)
    }
}
