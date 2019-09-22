use crate::{Error, parse_der};
use crate::der::Value;

#[derive(Debug)]
pub struct BasicConstraints<'a>(Vec<Value<'a>>);

impl<'a> BasicConstraints<'a> {
    pub fn new(data: &'a [u8]) -> Result<BasicConstraints<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(BasicConstraints(s));
        }

        Err(Error::X509Error)
    }

    pub fn is_ca(&self) -> Result<bool, Error> {
        if !self.0.is_empty() {
            if let Value::Boolean(ca) = &self.0[0] {
                return Ok(ca.to_bool());
            }
        }

        Ok(false)
    }

    pub fn path_len_constraint(&self) -> Result<Option<i64>, Error> {
        if self.0.is_empty() {
            // if sequence is empty this constraint doesn't make sense, since by default it's not a CA
            return Err(Error::X509Error);
        }
        if self.0.len() == 2 {
            if let Value::Integer(c) = &self.0[1] {
                return Ok(Some(c.to_i64()));
            } else {
                //it must be an integer, otherwise something is wrong
                return Err(Error::X509Error);
            }
        }
        Ok(None)
    }
}
