use ursa::cl::{RevocationKeyPrivate, RevocationKeyPublic};

use named_type::NamedType;
use serde::{de::IntoDeserializer, Deserialize};
use std::collections::HashSet;
use std::str::FromStr;

use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::rev_reg::RevocationRegistryId;
use crate::utils::qualifier::Qualifiable;
use crate::utils::validation::{Validatable, ValidationError};

pub const CL_ACCUM: &str = "CL_ACCUM";

#[derive(Deserialize, Debug, Serialize)]
pub struct RevocationRegistryConfig {
    pub issuance_type: Option<IssuanceType>,
    pub max_cred_num: Option<u32>,
}

#[allow(non_camel_case_types)]
#[derive(Deserialize, Debug, Serialize, PartialEq, Clone, Copy)]
pub enum IssuanceType {
    ISSUANCE_BY_DEFAULT,
    ISSUANCE_ON_DEMAND,
}

impl IssuanceType {
    pub fn to_bool(&self) -> bool {
        self.clone() == IssuanceType::ISSUANCE_BY_DEFAULT
    }
}

impl FromStr for IssuanceType {
    type Err = ValidationError;
    fn from_str(val: &str) -> Result<Self, ValidationError> {
        Self::deserialize(<&str as IntoDeserializer>::into_deserializer(val))
            .map_err(|_| invalid!("Invalid issuance type"))
    }
}

#[allow(non_camel_case_types)]
#[derive(Deserialize, Debug, Serialize, PartialEq, Clone, Copy)]
pub enum RegistryType {
    CL_ACCUM,
}

impl RegistryType {
    pub fn to_str(&self) -> &'static str {
        match *self {
            RegistryType::CL_ACCUM => CL_ACCUM,
        }
    }
}

impl FromStr for RegistryType {
    type Err = ValidationError;
    fn from_str(val: &str) -> Result<Self, ValidationError> {
        Self::deserialize(<&str as IntoDeserializer>::into_deserializer(val))
            .map_err(|_| invalid!("Invalid registry type"))
    }
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinitionValue {
    pub issuance_type: IssuanceType,
    pub max_cred_num: u32,
    pub public_keys: RevocationRegistryDefinitionValuePublicKeys,
    pub tails_hash: String,
    pub tails_location: String,
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinitionValuePublicKeys {
    pub accum_key: RevocationKeyPublic,
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinitionV1 {
    pub id: RevocationRegistryId,
    pub revoc_def_type: RegistryType,
    pub tag: String,
    pub cred_def_id: CredentialDefinitionId,
    pub value: RevocationRegistryDefinitionValue,
}

#[derive(Debug, Serialize, Deserialize, NamedType)]
#[serde(tag = "ver")]
pub enum RevocationRegistryDefinition {
    #[serde(rename = "1.0")]
    RevocationRegistryDefinitionV1(RevocationRegistryDefinitionV1),
}

impl RevocationRegistryDefinition {
    pub fn to_unqualified(self) -> RevocationRegistryDefinition {
        match self {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(rev_ref_def) => {
                RevocationRegistryDefinition::RevocationRegistryDefinitionV1(
                    RevocationRegistryDefinitionV1 {
                        id: rev_ref_def.id.to_unqualified(),
                        revoc_def_type: rev_ref_def.revoc_def_type,
                        tag: rev_ref_def.tag,
                        cred_def_id: rev_ref_def.cred_def_id.to_unqualified(),
                        value: rev_ref_def.value,
                    },
                )
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, NamedType)]
pub struct RevocationRegistryDefinitionPrivate {
    pub value: RevocationKeyPrivate,
}

#[derive(Debug, Deserialize, Serialize, Clone, NamedType)]
pub struct RevocationRegistryInfo {
    pub id: RevocationRegistryId,
    pub curr_id: u32,
    pub used_ids: HashSet<u32>,
}

impl Validatable for RevocationRegistryConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(num_) = self.max_cred_num {
            if num_ == 0 {
                return Err(invalid!("RevocationRegistryConfig validation failed: `max_cred_num` must be greater than 0"));
            }
        }
        Ok(())
    }
}

impl Validatable for RevocationRegistryDefinition {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(revoc_reg_def) => {
                revoc_reg_def.id.validate()?;
            }
        }
        Ok(())
    }
}
