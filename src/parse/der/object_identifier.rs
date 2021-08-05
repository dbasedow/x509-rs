use super::super::error::ParseError;
use super::{expect_type, DataType};
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier(Vec<u8>);

impl ObjectIdentifier {
    pub fn from_str(s: &str) -> Result<Self, ()> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 2 {
            return Err(());
        }

        let x = u8::from_str(parts[0]).map_err(|_| ())?;
        if x > 5 {
            return Err(());
        }

        let y = u8::from_str(parts[1]).map_err(|_| ())?;
        if y > 40 {
            return Err(());
        }

        let xy = x * 40 + y;
        let mut data: Vec<u8> = Vec::new();
        data.push(xy);

        for part in &parts[2..] {
            let part = u64::from_str(part).map_err(|_| ())?;
            if part <= 0x7f {
                data.push(part as u8);
            } else {
                data.extend_from_slice(&encode_oid_part(part));
            }
        }
        Ok(Self(data))
    }
}

fn encode_oid_part(n: u64) -> Vec<u8> {
    let mut res = Vec::new();
    let mut n = n;
    while n > 0 {
        let mut b = (n & 0x7f) as u8;

        // if this is not the lowest byte set bit 8 to 1
        if res.len() > 0 {
            b = b | 0x80;
        }

        res.push(b);
        n = n >> 7;
    }
    res.reverse();
    res
}

impl<'a> From<&'a ObjectIdentifier> for ObjectIdentifierRef<'a> {
    fn from(oid: &'a ObjectIdentifier) -> Self {
        Self(&oid.0)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifierRef<'a>(pub(crate) &'a [u8]);

impl<'a> ObjectIdentifierRef<'a> {
    pub fn to_parts(&self) -> Vec<u64> {
        let mut res = Vec::new();
        let data = self.0;
        let y = data[0] % 40;
        let x = (data[0] - y) / 40;

        res.push(x as u64);
        res.push(y as u64);

        let mut sub_id: u64 = 0;

        for &octet in &data[1..] {
            sub_id = sub_id << 7;
            sub_id += (octet & 0x7f) as u64;

            if octet & 0x80 == 0 {
                //last part of subid.
                res.push(sub_id);
                sub_id = 0;
            }
        }

        res
    }
}

impl<'a> Display for ObjectIdentifierRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        for (index, &sub_id) in self.to_parts().iter().enumerate() {
            if index > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", sub_id)?;
        }
        Ok(())
    }
}

impl<'a> Debug for ObjectIdentifierRef<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub fn expect_object_identifier(data: &[u8]) -> Result<(&[u8], ObjectIdentifierRef), ParseError> {
    let (rest, inner) = expect_type(data, DataType::ObjectIdentifier)?;

    Ok((rest, ObjectIdentifierRef(inner)))
}
