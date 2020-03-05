use std::str::FromStr;

use serde::{de::IntoDeserializer, Deserialize};
use ursa::cl::{
    CredentialPrimaryPublicKey, CredentialPrivateKey, CredentialPublicKey,
    CredentialRevocationPublicKey,
};

use crate::common::error::prelude::*;
use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::schema::SchemaId;
use crate::utils::qualifier::Qualifiable;
use crate::utils::validation::{Validatable, ValidationError};

use named_type::NamedType;

pub const CL_SIGNATURE_TYPE: &str = "CL";

#[derive(Deserialize, Debug, Serialize, PartialEq, Copy, Clone)]
pub enum SignatureType {
    CL,
}

impl SignatureType {
    pub fn to_str(&self) -> &'static str {
        match *self {
            SignatureType::CL => CL_SIGNATURE_TYPE,
        }
    }
}

impl FromStr for SignatureType {
    type Err = ValidationError;
    fn from_str(val: &str) -> Result<Self, ValidationError> {
        Self::deserialize(<&str as IntoDeserializer>::into_deserializer(val))
            .map_err(|_| invalid!("Invalid signature type"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDefinitionConfig {
    pub support_revocation: bool,
}

impl CredentialDefinitionConfig {
    pub fn new(support_revocation: bool) -> Self {
        Self { support_revocation }
    }
}

impl Default for CredentialDefinitionConfig {
    fn default() -> Self {
        Self {
            support_revocation: false,
        }
    }
}

impl Validatable for CredentialDefinitionConfig {}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialDefinitionData {
    pub primary: CredentialPrimaryPublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<CredentialRevocationPublicKey>,
}

impl CredentialDefinitionData {
    pub fn try_clone(&self) -> IndyResult<CredentialDefinitionData> {
        let primary = self.primary.try_clone()?;
        let revocation = self.revocation.clone();
        Ok(CredentialDefinitionData {
            primary,
            revocation,
        })
    }
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinitionV1 {
    pub id: CredentialDefinitionId,
    pub schema_id: SchemaId,
    #[serde(rename = "type")]
    pub signature_type: SignatureType,
    pub tag: String,
    pub value: CredentialDefinitionData,
}

impl CredentialDefinitionV1 {
    pub fn get_public_key(&self) -> IndyResult<CredentialPublicKey> {
        let key = CredentialPublicKey::build_from_parts(
            &self.value.primary,
            self.value.revocation.as_ref(),
        )?;
        Ok(key)
    }
}

impl Validatable for CredentialDefinitionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.id.validate()?;
        self.schema_id.validate()?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, NamedType)]
#[serde(tag = "ver")]
pub enum CredentialDefinition {
    #[serde(rename = "1.0")]
    CredentialDefinitionV1(CredentialDefinitionV1),
}

impl CredentialDefinition {
    pub fn to_unqualified(self) -> CredentialDefinition {
        match self {
            CredentialDefinition::CredentialDefinitionV1(cred_def) => {
                CredentialDefinition::CredentialDefinitionV1(CredentialDefinitionV1 {
                    id: cred_def.id.to_unqualified(),
                    schema_id: cred_def.schema_id.to_unqualified(),
                    signature_type: cred_def.signature_type,
                    tag: cred_def.tag,
                    value: cred_def.value,
                })
            }
        }
    }
}

impl Validatable for CredentialDefinition {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            CredentialDefinition::CredentialDefinitionV1(cred_def) => cred_def.validate(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, NamedType)]
pub struct CredentialDefinitionPrivateKey {
    pub value: CredentialPrivateKey,
}
