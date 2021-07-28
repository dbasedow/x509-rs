use crate::der::Integer;

pub struct TBSCertificateBuilder {
    serial_number: Option<Integer>,
    signature: Option<AlgorithmIdentifier>,
}
