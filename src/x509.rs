struct Certificate {
    tbs_certificate: TBSCertificate,
    //signature_algorithm: AlgorithmIdentifier,
    signature: Vec<u8>,
}

enum Algorithm {
    Sha256WithRSAEncryption,
}

struct TBSCertificate {}