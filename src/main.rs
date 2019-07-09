use std::fmt::{Display, Formatter, Debug};
use std::{fmt, env};
use std::string::FromUtf8Error;
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), Box<std::error::Error>> {
    if let Some(file_name) = env::args().last() {
        let mut f = File::open(file_name)?;
        let mut buf = Vec::with_capacity(8192);
        f.read_to_end(&mut buf)?;
        let (parsed, consumed) = parse_der(&buf)?;
        println!("parsed {} bytes", consumed);
        println!("{:#?}", parsed);
    }
    Ok(())
}

#[derive(Debug)]
enum Error {
    ParseError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Parse error")
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Error {
        Error::ParseError
    }
}

impl std::error::Error for Error {}

#[derive(PartialEq)]
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
                write!(f, ".")?;
            }
            write!(f, "{}", sub_id)?;
        }
        Ok(())
    }
}

impl Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(Debug, PartialEq)]
enum Value<'a> {
    Boolean(bool),
    Integer(i64),
    BitString(&'a [u8]),
    OctetString(&'a [u8]),
    Null,
    ObjectIdentifier(ObjectIdentifier),
    Sequence(Vec<Value<'a>>),
    //TODO: use different type
    UTCTime(String),
    //TODO: use different type
    GeneralizedTime(String),
    PrintableString(String),
    Utf8String(String),
    Set(Vec<Value<'a>>),
    ContextSpecific(u8, Box<Value<'a>>),
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

fn parse_integer(data: &[u8]) -> Result<Value, Error> {
    if data.len() > 8 {
        return Err(Error::ParseError);
    }

    let mut res: i64 = 0;
    let a = data[0] as i8;
    res += a as i64;

    for &octet in &data[1..] {
        res = res << 8;
        res = res | octet as i64;
    }
    Ok(Value::Integer(res))
}

#[test]
fn test_parse_integer() {
    let d: Vec<u8> = vec![0x80];
    let res = parse_integer(&d);
    assert!(res.is_ok());
    assert_eq!(res.ok().unwrap(), Value::Integer(-128));

    let d: Vec<u8> = vec![0xFF, 0x7F];
    let res = parse_integer(&d);
    assert!(res.is_ok());
    assert_eq!(res.ok().unwrap(), Value::Integer(-129));

    let d: Vec<u8> = vec![0x00, 0x80];
    let res = parse_integer(&d);
    assert!(res.is_ok());
    assert_eq!(res.ok().unwrap(), Value::Integer(128));
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

fn parse_set(data: &[u8]) -> Result<Value, Error> {
    let mut data = &data[..];
    let mut elements: Vec<Value> = Vec::new();

    while data.len() > 0 {
        //let (tlv, consumed) = get_tlv(data)?;
        let (value, consumed) = parse_der(&data)?;
        elements.push(value);
        data = &data[consumed..];
    }

    Ok(Value::Set(elements))
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

fn parse_boolean(data: &[u8]) -> Result<Value, Error> {
    if data.len() != 1 {
        return Err(Error::ParseError);
    }
    Ok(Value::Boolean(data[0] == 0xff))
}

fn parse_der(data: &[u8]) -> Result<(Value, usize), Error> {
    let (tlv, consumed) = get_tlv(data)?;
    if tlv.is_context_specific() && tlv.is_constructed_type() {
        let (v, _) = parse_der(&tlv.value)?;
        return Ok((Value::ContextSpecific(tlv.get_data_type(), Box::new(v)), consumed));
    }

    let value = match tlv.get_data_type() {
        0x01 => parse_boolean(&tlv.value)?,
        0x02 => parse_integer(&tlv.value)?,
        0x03 => Value::BitString(&tlv.value),
        0x04 => Value::OctetString(&tlv.value),
        0x05 => Value::Null,
        0x06 => parse_object_identifier(&tlv.value)?,
        0x0c => Value::Utf8String(String::from_utf8(data.to_vec())?),
        0x10 => parse_sequence(&tlv.value)?,
        0x11 => parse_set(&tlv.value)?,
        0x13 => Value::PrintableString(String::from_utf8(data.to_vec())?),
        0x17 => parse_utc_time(&tlv.value)?,
        0x18 => parse_generalized_time(&tlv.value)?,
        t => {
            unimplemented!("{} is not implemented", t);
        }
    };
    Ok((value, consumed))
}

#[test]
fn test_parse_der() {
    let d = hex::decode("308202bc308201a4a003020102020404c5fefc300d06092a864886f70d01010b0500302e312c302a0603550403132359756269636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f32303530303930343030303030305a306d310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3126302406035504030c1d59756269636f205532462045452053657269616c2038303038343733323059301306072a8648ce3d020106082a8648ce3d030107034200041cd8da7611a3f5ef1f885e950ba65d80e334855391584bd47f5b719c53235c2421e4e399bdb5736782419093576661493c914c2e6724df9394fcfa7dea8b1804a36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e313013060b2b0601040182e51c0201010404030205203021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b0500038201010077184cef752d1a05f30a5385dc2d86f8fac0637170b02262a5195cf5fed036fe00654e0d2915bc45529a3f895e6ac1ccd41e977156e00ba93a06e0ac99a6716584059c974a9450b58725d8b4cd534f88cfd59bc8734dd70409f726c5c23eb4f3106ea0d442d2b1bcc2061b302e2eb3245a76dddd60e55d422d1c7da92c541d9534a9f0fadb505162a866c3c7b6ecc5c7c3656b32d005ea755b64f414238d1441bbc7f97e65c7cd853d776b301b6aeac9d89d3f7dfe87d0f5c93fa87e39b9dee317f3d3ef2e8dfb560d44a1f686a255161ffad81a9bfb7338ac84537f15da5895d75cccc87296ad788ad007f20e06f9f24cb61d2ae7fc0804e4c5bfa1783f0977").unwrap();
    let res = parse_der(&d);
    assert!(res.is_ok());
    let (value, consumed) = res.ok().unwrap();
    //assert_eq!(consumed, 704);
    println!("{:#?}", value);
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
    if let (Value::ObjectIdentifier(value), _) = res.ok().unwrap() {
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

    fn is_context_specific(&self) -> bool {
        self.tag & 0x80 == 0x80
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

mod x509;
