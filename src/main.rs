use std::fmt::{Display, Formatter};
use std::{io, fmt};
use std::intrinsics::write_bytes;

fn main() {
    println!("Hello, world!");
}

enum Error {
    ParseError,
}

#[derive(Debug)]
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

#[derive(Debug)]
enum Value {
    ObjectIdentifier(ObjectIdentifier),
    Sequence(Vec<Value>),
    //TODO: use different type
    UTCTime(String),
    //TODO: use different type
    GeneralizedTime(String),
}

fn parse_object_identifier(data: &[u8]) -> Result<Value, Error> {
    if data.len() < 1 {
        return Err(Error::ParseError);
    }

    let mut res = ObjectIdentifier::new();

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

    Ok(Value::ObjectIdentifier(res))
}

#[test]
fn test_parse_object_identifier() {
    let d = hex::decode("2a864886f70d").unwrap();
    let res = parse_object_identifier(&d);
    assert!(res.is_ok());
    let oid = res.ok().unwrap();
    if let Value::ObjectIdentifier(oid) = oid {
        assert_eq!("1.2.840.113549", format!("{}", oid));
    } else {
        panic!("wrong type");
    }
}

fn parse_sequence(data: &[u8]) -> Result<Value, Error> {
    let mut data = &data[..];
    let mut elements: Vec<Value> = Vec::new();

    while data.len() > 0 {
        //let (tlv, consumed) = get_tlv(data)?;
        let (value, consumed) = parse_der(&data)?;
        elements.push(value);
        data = &data[consumed..];
    }

    Ok(Value::Sequence(elements))
}

fn parse_utc_time(data: &[u8]) -> Result<Value, Error> {
    if let Ok(s) = String::from_utf8(data.to_vec()) {
        Ok(Value::UTCTime(s))
    } else {
        Err(Error::ParseError)
    }
}

fn parse_generalized_time(data: &[u8]) -> Result<Value, Error> {
    if let Ok(s) = String::from_utf8(data.to_vec()) {
        Ok(Value::GeneralizedTime(s))
    } else {
        Err(Error::ParseError)
    }
}

fn parse_der(data: &[u8]) -> Result<(Value, usize), Error> {
    let (tlv, consumed) = get_tlv(data)?;
    let (value, _) = match tlv.get_data_type() {
        0x06 => (parse_object_identifier(&tlv.value)?, tlv.length),
        0x10 => (parse_sequence(&tlv.value)?, tlv.length),
        0x17 => (parse_utc_time(&tlv.value)?, tlv.length),
        0x18 => (parse_generalized_time(&tlv.value)?, tlv.length),
        t => {
            unimplemented!("{} is not implemented", t);
        }
    };
    Ok((value, consumed))
}

#[test]
fn test_parse_der_sequence() {
    let d = hex::decode("3020170d3134303830313030303030305a180f32303530303930343030303030305a").unwrap();
    let res = parse_der(&d);
    assert!(res.is_ok());
}

#[test]
fn test_parse_der_object_id() {
    let d = hex::decode("06062a864886f70d").unwrap();
    let res = parse_der(&d);
    assert!(res.is_ok());
    if let (Value::ObjectIdentifier(value), consumed) = res.ok().unwrap() {
        assert_eq!("1.2.840.113549", format!("{}", value));
    } else {
        panic!("wrong value type");
    }
}

struct TLV<'a> {
    tag: u8,
    length: usize,
    value: &'a [u8],
}

impl<'a> TLV<'a> {
    fn get_data_type(&self) -> u8 {
        self.tag & 0x1f
    }

    fn is_constructed_type(&self) -> bool {
        self.tag & 0x20 == 0x20
    }
}

fn get_tlv(data: &[u8]) -> Result<(TLV, usize), Error> {
    if data.len() < 2 {
        // we need at least a tag and a length (which may be 0)
        return Err(Error::ParseError);
    }

    let mut consumed: usize = 0;

    // we only handle single byte tags
    let tag = data[0];
    consumed += 1;

    let first_length_octet = data[consumed];
    consumed += 1;

    let long_length_encoding = first_length_octet & 0x80 == 0x80;

    let length;
    if long_length_encoding {
        let length_length = (first_length_octet & 0x7f) as usize;
        if length_length > 8 {
            return Err(Error::ParseError);
        }
        let mut tmp_length: usize = 0;
        for &octet in &data[2..2 + length_length] {
            consumed += 1;
            tmp_length = tmp_length << 8;
            tmp_length += octet as usize;
        }
        length = tmp_length;
    } else {
        length = (first_length_octet & 0x7f) as usize;
    }

    if length + consumed > data.len() {
        return Err(Error::ParseError);
    }

    Ok((TLV {
        tag,
        length,
        value: &data[consumed..consumed + length],
    }, consumed + length))
}

#[test]
fn test_get_tlv() {
    let d = hex::decode("06062a864886f70d").unwrap();
    let res = get_tlv(&d);
    assert!(res.is_ok());
    let (tlv, consumed) = res.ok().unwrap();
    assert_eq!(consumed, 8);
    assert_eq!(tlv.tag, 0x06);
    assert_eq!(tlv.length, 6);
    assert_eq!(hex::encode(tlv.value), "2a864886f70d");
}
