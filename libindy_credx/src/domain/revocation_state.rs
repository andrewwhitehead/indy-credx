use std::collections::HashMap;
use ursa::cl::{RevocationRegistry, Witness};

use crate::utils::validation::{Validatable, ValidationError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationState {
    pub witness: Witness,
    pub rev_reg: RevocationRegistry,
    pub timestamp: u64,
}

impl Validatable for RevocationState {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.timestamp == 0 {
            return Err(invalid!(
                "RevocationState validation failed: `timestamp` must be greater than 0",
            ));
        }
        Ok(())
    }
}

pub type RevocationStates = HashMap<String, HashMap<u64, RevocationState>>;
