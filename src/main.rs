use std::fmt::Formatter;
use std::{fmt, env};
use std::string::FromUtf8Error;
use std::fs::File;
use std::io::Read;
use std::num::ParseIntError;
use crate::x509::Certificate;
use untrusted::Input;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(file_name) = env::args().last() {
        let mut f = File::open(file_name)?;
        let mut buf = Vec::with_capacity(8192);
        f.read_to_end(&mut buf)?;
        let (parsed, _) = der::parse_der(&buf)?;

        let cert = Certificate::from_value(parsed);
        println!("version: {}", cert.version()?);
        println!("serial: {}", cert.serial()?);
        let issuer = cert.issuer()?;
        print!("issuer: ");
        for (i, rdn) in issuer.iter().enumerate() {
            if i != 0 {
                print!(", ");
            }
            print!("{}", rdn);
        }
        println!();

        let subject = cert.subject()?;
        print!("subject: ");
        for (i, rdn) in subject.iter().enumerate() {
            if i != 0 {
                print!(", ");
            }
            print!("{}", rdn);
        }
        println!();
        println!("valid from: {}", cert.valid_from()?);
        println!("valid to: {}", cert.valid_to()?);

        println!("Extensions");
        for ext in cert.extensions()? {
            print!("  {}:", ext.object_identifier());
            if ext.critical() {
                print!(" critical");
            }
            println!();
            if let Ok(data) = ext.data() {
                println!("    {:?}", data);
            } else {
                println!("    {:?}", ext.data_raw());
            }
        }

        let key = cert.public_key()?;
        let signature = cert.signature()?;
        let msg = cert.raw_tbs_cert()?;

        let res = ring::signature::verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256,
                                          Input::from(key),
                                          Input::from(msg),
                                          Input::from(signature),
        );
        if res.is_ok() {
            println!("signature validation successful");
        } else {
            println!("signature validation failed");
        }
    }
    Ok(())
}

mod x509;
mod der;
mod error;
