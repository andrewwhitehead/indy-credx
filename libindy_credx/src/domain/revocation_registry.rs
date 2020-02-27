use named_type::NamedType;
use ursa::cl::RevocationRegistry as CryptoRevocationRegistry;

use crate::utils::validation::Validatable;

#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationRegistryV1 {
    pub value: CryptoRevocationRegistry,
}

#[derive(Debug, Serialize, Deserialize, NamedType)]
#[serde(tag = "ver")]
pub enum RevocationRegistry {
    #[serde(rename = "1.0")]
    RevocationRegistryV1(RevocationRegistryV1),
}

impl From<RevocationRegistry> for RevocationRegistryV1 {
    fn from(rev_reg: RevocationRegistry) -> Self {
        match rev_reg {
            RevocationRegistry::RevocationRegistryV1(rev_reg) => rev_reg,
        }
    }
}

impl Validatable for RevocationRegistry {}
