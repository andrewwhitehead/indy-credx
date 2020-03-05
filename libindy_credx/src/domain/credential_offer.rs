use ursa::cl::{CredentialKeyCorrectnessProof, Nonce};

use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::schema::SchemaId;
use crate::utils::qualifier::Qualifiable;
use crate::utils::validation::{Validatable, ValidationError};

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialOffer {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub key_correctness_proof: CredentialKeyCorrectnessProof,
    pub nonce: Nonce,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_name: Option<String>,
}

impl CredentialOffer {
    pub fn to_unqualified(self) -> CredentialOffer {
        let method_name = self.cred_def_id.get_method().map(str::to_owned);
        CredentialOffer {
            method_name,
            schema_id: self.schema_id.to_unqualified(),
            cred_def_id: self.cred_def_id.to_unqualified(),
            key_correctness_proof: self.key_correctness_proof,
            nonce: self.nonce,
        }
    }
}

impl Validatable for CredentialOffer {
    fn validate(&self) -> Result<(), ValidationError> {
        self.schema_id.validate()?;
        self.cred_def_id.validate()?;
        Ok(())
    }
}
