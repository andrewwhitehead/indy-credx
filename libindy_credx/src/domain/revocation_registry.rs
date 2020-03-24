use ursa::cl::RevocationRegistry as CryptoRevocationRegistry;

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
