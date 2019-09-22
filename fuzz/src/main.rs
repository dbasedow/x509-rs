#[macro_use]
extern crate afl;

use x509::parse_der;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = parse_der(data);
    });
}
