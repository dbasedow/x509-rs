use std::fmt::{Display, Formatter};
use std::{io, fmt};
use std::intrinsics::write_bytes;

fn main() {
    println!("Hello, world!");
}

enum Error {
    ParseError,
}

struct ObjectIdentifier(Vec<u64>);

impl ObjectIdentifier {
    fn new() -> ObjectIdentifier {
        ObjectIdentifier(Vec::new())
    }

    fn push(&mut self, id: u64) {
        self.0.push(id)
    }
}

impl Display for ObjectIdentifier {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        for (index, &sub_id) in self.0.iter().enumerate() {
            if index > 0 {
                write!(f, ".");
            }
            write!(f, "{}", sub_id);
        }
        Ok(())
    }
}

enum Value {
    ObjectIdentifier(ObjectIdentifier),
}

fn parse_object_identifier(data: &[u8]) -> Result<ObjectIdentifier, Error> {
    if data.len() < 1 {
        return Err(Error::ParseError);
    }

    let mut res = ObjectIdentifier::new();

    let y = data[0] % 40;
    let x = (data[0] - y) / 40;

    res.push(x as u64);
    res.push(y as u64);

    let mut sub_id_octets: Vec<u8> = Vec::new();

    for &octet in &data[1..] {
        if octet & 0x80 == 0 {
            //last part of subid.
            sub_id_octets.push(octet);
            let sub_id = sub_id_octs_to_u64(&sub_id_octets);
            res.push(sub_id);
            sub_id_octets.truncate(0);
        } else {
            sub_id_octets.push(octet & 0x7f);
        }
    }

    Ok(res)
}

#[test]
fn test_parse_object_identifier() {
    let d = hex::decode("2a864886f70d").unwrap();
    let res = parse_object_identifier(&d);
    assert!(res.is_ok());
    let oid = res.ok().unwrap();
    assert_eq!("1.2.840.113549", format!("{}", oid));
}

fn sub_id_octs_to_u64(octs: &[u8]) -> u64 {
    let mut res = 0;

    for (index, &octet) in octs.iter().rev().enumerate() {
        res += octet as u64 * (0x01 << (7 * index as u64));
    }

    res
}

#[test]
fn test_sub_id_octs_to_u64() {
    let d: Vec<u8> = vec![6, 72];
    assert_eq!(840, sub_id_octs_to_u64(&d));

    let d: Vec<u8> = vec![6, 119, 13];
    assert_eq!(113549, sub_id_octs_to_u64(&d));
}