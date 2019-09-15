use std::{env, io};
use std::fs::File;
use std::io::{BufRead, BufReader};
use untrusted::Input;
use std::collections::HashMap;
use ring::signature::VerificationAlgorithm;
use x509::{der, Certificate, Error};
use x509::extensions::ExtensionType;
use x509::x509::SignatureAlgorithm;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(file_name) = env::args().last() {
        let f = File::open(file_name)?;
        let reader = BufReader::new(f);
        let mut c = 0;
        let mut dist: HashMap<String, u32> = HashMap::new();
        for line in reader.lines() {
            println!("{}", c);
            match line {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("error: {}", e),
                Ok(_) => {}
            }
            let line = line.unwrap();
            let buf = base64::decode(&line).unwrap();
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

            if let Err(_e) = cert.signature_algorithm() {
                println!("error reading signature algorithm");
            }

            if let Some(extensions) = cert.extensions()? {
                println!("Extensions");
                for ext in extensions {
                    let s = format!("{}", ext.object_identifier());
                    if s == "1.3.6.1.4.1.11129.2.4.2".to_string() {
                        //eprintln!("{:x?}", ext.data_raw());
                    }
                    print!("  {}:", s);
                    if ext.critical() {
                        let &c = dist.get(&s).unwrap_or(&0);
                        let d = c + 1;
                        dist.insert(s, d);
                        print!(" critical");
                    }
                    println!();
                    match ext.data()? {
                        ExtensionType::KeyUsage(ku) => println!("digital_signature: {}", ku.digital_signature()?),
                        e => println!("{:x?}", e),
                    }
                }
            }

            if cert.self_signed()? {
                println!("self signed");
                let res = check_self_signed_sig(&cert);
                if res.is_ok() && res.unwrap() {
                    println!("signature validation successful. algo: {:?}", cert.signature_algorithm());
                } else {
                    println!("signature validation failed. algo: {:?}", cert.signature_algorithm());
                }
            }

            c += 1;
        }

        eprintln!();
        eprintln!("OIDs from extensions");
        for (oid, cnt) in dist.iter() {
            eprintln!("{}: {}", oid, cnt);
        }
    }

    Ok(())
}

fn check_self_signed_sig(cert: &Certificate) -> Result<bool, Error> {
    let alg: &dyn VerificationAlgorithm = match cert.signature_algorithm()? {
        SignatureAlgorithm::Pkcs1Sha1Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA1,
        SignatureAlgorithm::Pkcs1Sha256Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        SignatureAlgorithm::Pkcs1Sha384Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureAlgorithm::Pkcs1Sha512Rsa => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        SignatureAlgorithm::Pkcs1Sha256Ecdsa => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SignatureAlgorithm::Pkcs1Sha384Ecdsa => &ring::signature::ECDSA_P384_SHA384_FIXED,
        _ => return Err(Error::X509Error),
    };

    let key = cert.public_key()?;
    let signature = cert.signature()?;
    let msg = cert.raw_tbs_cert()?;

    let res = ring::signature::verify(alg,
                                      Input::from(key),
                                      Input::from(msg),
                                      Input::from(signature),
    );

    Ok(res.is_ok())
}
