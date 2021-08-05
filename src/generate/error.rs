#[derive(Debug)]
pub enum EncodingError {
    StringNotAscii,
    MissingRequiredField(&'static str),
}
