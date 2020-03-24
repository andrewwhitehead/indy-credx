use ursa::cl::RevocationRegistry as CryptoRevocationRegistry;
use ursa::cl::RevocationRegistryDelta as CryptoRevocationRegistryDelta;

use std::collections::HashSet;

use super::revocation_registry_delta::{RevocationRegistryDelta, RevocationRegistryDeltaV1};
use crate::utils::validation::Validatable;

#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationRegistryV1 {
    pub value: CryptoRevocationRegistry,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum RevocationRegistry {
    #[serde(rename = "1.0")]
    RevocationRegistryV1(RevocationRegistryV1),
}

impl Validatable for RevocationRegistry {}

impl RevocationRegistry {
    pub fn initial_delta(&self) -> RevocationRegistryDelta {
        match self {
            Self::RevocationRegistryV1(v1) => {
                RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
                    value: {
                        let empty = HashSet::new();
                        CryptoRevocationRegistryDelta::from_parts(None, &v1.value, &empty, &empty)
                    },
                })
            }
        }
    }
}
