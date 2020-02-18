use crate::common::error::IndyResult;

pub trait Validatable {
    fn validate(&self) -> IndyResult<()> {
        Ok(())
    }
}
