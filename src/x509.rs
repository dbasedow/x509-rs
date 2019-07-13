use crate::Value;
use crate::Error;

pub struct Certificate<'a>(Value<'a>);

impl<'a> Certificate<'a> {
    pub fn from_value(value: Value<'a>) -> Certificate<'a> {
        Certificate(value)
    }

    pub fn get_serial(&self) -> Result<i64, Error> {
        if let Value::Sequence(certificate) = &self.0 {
            if let Value::Sequence(tbs_cert) = &certificate[0] {
                if let Value::Integer(serial) = &tbs_cert[1] {
                    return Ok(serial.to_i64());
                }
            }
        }
        Err(Error::X509Error)
    }
}
