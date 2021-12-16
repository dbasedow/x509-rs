use crate::{Error, parse_der};
use crate::extensions::GeneralName;
use crate::der::Value;

#[derive(Debug)]
pub struct CrlDistributionPoints<'a>(Vec<Value<'a>>);

impl<'a> CrlDistributionPoints<'a> {
    pub fn new(data: &'a [u8]) -> Result<CrlDistributionPoints<'a>, Error> {
        if let (Value::Sequence(s, _), _) = parse_der(data)? {
            return Ok(CrlDistributionPoints(s));
        }

        Err(Error::X509Error)
    }

    pub fn distribution_points(&'a self) -> Result<Vec<DistributionPoint<'a>>, Error> {
        let mut points = Vec::with_capacity(self.0.len());
        for v in &self.0 {
            points.push(DistributionPoint::new(v)?);
        }
        Ok(points)
    }
}

#[derive(Debug, Default)]
pub struct DistributionPoint<'a> {
    name: Option<DistributionPointName<'a>>,
    //reasons
    crl_issuer: Option<GeneralName<'a>>,
}

impl<'a> DistributionPoint<'a> {
    fn new(value: &'a Value) -> Result<DistributionPoint<'a>, Error> {
        if let Value::Sequence(seq, _) = value {
            let mut distribution_point = DistributionPoint::default();
            for field in seq {
                if let Value::ContextSpecific(ctx, content) = field {
                    match ctx {
                        0 => distribution_point.name = Some(DistributionPointName::new(content)?),
                        2 => distribution_point.crl_issuer = Some(GeneralName::new(content)?),
                        c => unimplemented!("distribution point context {}", c),
                    }
                }
            }
            return Ok(distribution_point);
        }

        Err(Error::X509Error)
    }
}

#[derive(Debug)]
pub enum DistributionPointName<'a> {
    FullName(GeneralName<'a>)
}

impl<'a> DistributionPointName<'a> {
    fn new(value: &'a Value) -> Result<DistributionPointName<'a>, Error> {
        if let Value::ContextSpecific(ctx, content) = value {
            match ctx {
                0 => return Ok(DistributionPointName::FullName(GeneralName::new(content)?)),
                c => unimplemented!("DistributionPointName context {}", c),
            }
        }

        Err(Error::X509Error)
    }
}
