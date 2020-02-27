use ursa::cl::RevocationRegistryDelta as RegistryDelta;

use crate::utils::validation::Validatable;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDeltaV1 {
    pub value: RegistryDelta,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum RevocationRegistryDelta {
    #[serde(rename = "1.0")]
    RevocationRegistryDeltaV1(RevocationRegistryDeltaV1),
}

impl Validatable for RevocationRegistryDelta {}
