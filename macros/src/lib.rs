use proc_macro::TokenStream;
use std::str::FromStr;
use syn::{parse_macro_input, LitStr};

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

fn from_str(s: &str) -> Result<Vec<u8>, ()> {
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

    Ok(data)
}

#[proc_macro]
pub fn oid_str_to_bytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let str_value = input.value();
    let parsed = from_str(&str_value).expect("parsing object identifier failed");
    let s = format!("&{:?}", &parsed);

    s.parse().unwrap()
}
