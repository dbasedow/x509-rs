use crate::der::{Value, ObjectIdentifier};
use crate::{parse_der, Error};

#[derive(Debug)]
pub struct CertificatePolicies<'a>(Vec<Value<'a>>);

impl<'a> CertificatePolicies<'a> {
    pub fn new(data: &'a [u8]) -> Result<CertificatePolicies, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(CertificatePolicies(s));
        }

        Err(Error::X509Error)
    }

    pub fn policy_information(&'a self) -> Result<Vec<PolicyInformation<'a>>, Error> {
        let mut res = Vec::with_capacity(self.0.len());
        for v in &self.0 {
            res.push(PolicyInformation::new(v)?);
        }

        Ok(res)
    }
}

#[derive(Debug)]
pub struct PolicyInformation<'a>(&'a ObjectIdentifier<'a>, Option<Vec<PolicyQualifierInfo>>);

impl<'a> PolicyInformation<'a> {
    pub fn new(value: &'a Value<'a>) -> Result<PolicyInformation, Error> {
        if let Value::Sequence(seq, _) = value {
            if !seq.is_empty() {
                if let Value::ObjectIdentifier(policy_identifier) = &seq[0] {
                    let mut policy_qualifier_info = None;
                    if seq.len() == 2 {
                        if let Value::Sequence(seq, _) = &seq[1] {
                            let mut res = Vec::with_capacity(seq.len());
                            for v in seq {
                                res.push(PolicyQualifierInfo::new(v)?);
                            }
                            policy_qualifier_info = Some(res);
                        }
                    } else {
                        policy_qualifier_info = None;
                    }
                    let policy_information = PolicyInformation(policy_identifier, policy_qualifier_info);
                    return Ok(policy_information);
                }
            }
        }
        Err(Error::X509Error)
    }

    pub fn policy_identifier(&self) -> &'a ObjectIdentifier<'a> {
        self.0
    }

    pub fn policy_qualifiers(&self) -> Option<&Vec<PolicyQualifierInfo>> {
        self.1.as_ref()
    }
}

#[derive(Debug)]
pub enum PolicyQualifierInfo {
    CpsUri(String),
    UserNotice(UserNotice),
}

const CPS_POLICY_QUALIFIER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 2, 1]);
const USER_NOTICE_POLICY_QUALIFIER_OID: &ObjectIdentifier<'static> = &ObjectIdentifier(&[43, 6, 1, 5, 5, 7, 2, 2]);

impl PolicyQualifierInfo {
    fn new<'a>(value: &'a Value<'a>) -> Result<PolicyQualifierInfo, Error> {
        if let Value::Sequence(seq, _) = value {
            if seq.len() != 2 {
                return Err(Error::X509Error);
            }
            if let Value::ObjectIdentifier(o) = &seq[0] {
                match (o, &seq[1]) {
                    (CPS_POLICY_QUALIFIER_OID, Value::IA5String(s)) => return Ok(PolicyQualifierInfo::CpsUri(s.to_string()?)),
                    (USER_NOTICE_POLICY_QUALIFIER_OID, v) => return Ok(PolicyQualifierInfo::UserNotice(UserNotice::new(v)?)),
                    (o, _) => unimplemented!("{}", o),
                }
            }
        }
        Err(Error::X509Error)
    }
}

#[derive(Debug, Default)]
pub struct UserNotice {
    notice_ref: Option<NoticeReference>,
    explicit_text: Option<String>,
}

impl UserNotice {
    fn new<'a>(value: &'a Value<'a>) -> Result<UserNotice, Error> {
        if let Value::Sequence(seq, _) = value {
            let mut result = UserNotice::default();
            if seq.len() > 2 {
                return Err(Error::X509Error);
            }
            for v in seq {
                if let Value::Sequence(_, _) = v {
                    result.notice_ref = Some(NoticeReference::new(v)?);
                } else {
                    result.explicit_text = Some(display_string_to_string(v)?);
                }
            }
            return Ok(result);
        }
        Err(Error::X509Error)
    }

    pub fn notice_ref(&self) -> Option<&NoticeReference> {
        self.notice_ref.as_ref()
    }

    pub fn explicit_text(&self) -> Option<&String> {
        self.explicit_text.as_ref()
    }
}

#[derive(Debug)]
pub struct NoticeReference {
    organization: String,
    notice_numbers: Vec<i64>,
}

impl NoticeReference {
    fn new<'a>(value: &'a Value<'a>) -> Result<NoticeReference, Error> {
        if let Value::Sequence(seq, _) = value {
            if seq.len() != 2 {
                return Err(Error::X509Error);
            }
            let organization = display_string_to_string(&seq[0])?;
            if let Value::Sequence(seq, _) = &seq[1] {
                let mut notice_numbers = Vec::with_capacity(seq.len());
                for i in seq {
                    if let Value::Integer(i) = i {
                        notice_numbers.push(i.to_i64());
                    } else {
                        return Err(Error::X509Error);
                    }
                }
                return Ok(NoticeReference {
                    organization,
                    notice_numbers,
                });
            } else {
                return Err(Error::X509Error);
            }
        }
        Err(Error::X509Error)
    }

    pub fn organization(&self) -> &String {
        &self.organization
    }

    pub fn notice_numbers(&self) -> &Vec<i64> {
        &self.notice_numbers
    }
}

fn display_string_to_string<'a>(value: &'a Value<'a>) -> Result<String, Error> {
    Ok(match value {
        Value::IA5String(txt) => txt.to_string()?,
        Value::BMPString(txt) => txt.to_string(),
        Value::Utf8String(txt) => txt.to_string(),
        Value::PrintableString(txt) => txt.to_string(),
        Value::T61String(txt) => txt.to_string(),
        Value::VisibleString(txt) => txt.to_string(),
        d => unimplemented!("{:?}", d),
    })
}
