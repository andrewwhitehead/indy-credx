use ursa::cl::MasterSecret as CryptoMasterSecret;

use crate::utils::validation::Validatable;

#[derive(Debug, Deserialize, Serialize)]
pub struct MasterSecret {
    pub value: CryptoMasterSecret,
}

impl Validatable for MasterSecret {}
