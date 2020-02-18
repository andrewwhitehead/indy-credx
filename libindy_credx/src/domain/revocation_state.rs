use std::collections::HashMap;
use ursa::cl::{RevocationRegistry, Witness};

use named_type::NamedType;

use crate::common::error::prelude::*;
use crate::utils::validation::Validatable;

#[derive(Clone, Debug, Serialize, Deserialize, NamedType)]
pub struct RevocationState {
    pub witness: Witness,
    pub rev_reg: RevocationRegistry,
    pub timestamp: u64,
}

impl Validatable for RevocationState {
    fn validate(&self) -> IndyResult<()> {
        if self.timestamp == 0 {
            return Err(input_err(
                "RevocationState validation failed: `timestamp` must be greater than 0",
            ));
        }
        Ok(())
    }
}

pub type RevocationStates = HashMap<String, HashMap<u64, RevocationState>>;
