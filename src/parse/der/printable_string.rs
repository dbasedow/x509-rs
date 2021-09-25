use std::fmt::{self, Debug, Display, Formatter};

#[derive(PartialEq)]
pub struct PrintableStringRef<'a>(&'a [u8]);

impl<'a> PrintableStringRef<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl<'a> Display for PrintableStringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            write!(f, "{}", s)
        } else {
            Err(fmt::Error::default())
        }
    }
}

impl<'a> Debug for PrintableStringRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.debug_tuple("PrintableStringRef").field(&format!("{}", self)).finish()
    }
}
