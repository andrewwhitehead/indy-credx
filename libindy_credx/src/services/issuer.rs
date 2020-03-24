use std::collections::HashSet;
use std::iter::FromIterator;

use crate::common::did::DidValue;
use crate::common::error::prelude::*;
use crate::domain::credential::{Credential, CredentialValues};
use crate::domain::credential_definition::{
    CredentialDefinition, CredentialDefinitionConfig, CredentialDefinitionData,
    CredentialDefinitionV1, SignatureType,
};
use crate::domain::credential_offer::CredentialOffer;
use crate::domain::credential_request::CredentialRequest;
use crate::domain::revocation_registry::{RevocationRegistry, RevocationRegistryV1};
use crate::domain::revocation_registry_definition::{
    IssuanceType, RegistryType, RevocationRegistryDefinition, RevocationRegistryDefinitionV1,
    RevocationRegistryDefinitionValue, RevocationRegistryDefinitionValuePublicKeys,
};
use crate::domain::revocation_registry_delta::{
    RevocationRegistryDelta, RevocationRegistryDeltaV1,
};
use crate::domain::schema::{AttributeNames, Schema, SchemaV1};
use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::rev_reg::RevocationRegistryId;
use crate::identifiers::schema::SchemaId;
use crate::services::helpers::*;
use crate::utils::qualifier::Qualifiable;
use crate::utils::validation::Validatable;

use super::tails::{TailsFileReader, TailsReader, TailsWriter};
use super::{
    new_nonce, CredentialKeyCorrectnessProof, CredentialPrivateKey, CryptoIssuer,
    CryptoRevocationRegistryDelta, RevocationKeyPrivate, Witness,
};

pub struct Issuer {}

impl Issuer {
    pub fn new_schema(
        origin_did: &DidValue,
        schema_name: &str,
        schema_version: &str,
        attr_names: AttributeNames,
    ) -> IndyResult<Schema> {
        trace!("new_schema >>> origin_did: {:?}, schema_name: {:?}, schema_version: {:?}, attr_names: {:?}",
            origin_did, schema_name, schema_version, attr_names);

        origin_did.validate()?;
        let schema_id = SchemaId::new(&origin_did, schema_name, schema_version);
        let schema = SchemaV1 {
            id: schema_id,
            name: schema_name.to_string(),
            version: schema_version.to_string(),
            attr_names,
            seq_no: None,
        };
        Ok(Schema::SchemaV1(schema))
    }

    pub fn make_credential_definition_id(
        origin_did: &DidValue,
        schema_id: &SchemaId,
        schema_seq_no: Option<u32>,
        tag: &str,
        signature_type: SignatureType,
    ) -> IndyResult<(CredentialDefinitionId, SchemaId)> {
        let schema_id = match (origin_did.get_method(), schema_id.get_method()) {
            (None, Some(_)) => {
                return Err(input_err(
                    "Cannot use an unqualified Origin DID with fully qualified Schema ID",
                ));
            }
            (method, _) => schema_id.default_method(method),
        };
        let schema_infix_id = schema_seq_no
            .map(|n| SchemaId(n.to_string()))
            .unwrap_or(SchemaId(schema_id.0.clone()));

        Ok((
            CredentialDefinitionId::new(
                origin_did,
                &schema_infix_id,
                &signature_type.to_str(),
                tag,
            ),
            schema_infix_id,
        ))
    }

    pub fn new_credential_definition(
        origin_did: &DidValue,
        schema: &Schema,
        tag: &str,
        signature_type: SignatureType,
        config: CredentialDefinitionConfig,
    ) -> IndyResult<(
        CredentialDefinition,
        CredentialPrivateKey,
        CredentialKeyCorrectnessProof,
    )> {
        trace!(
            "new_credential_definition >>> schema: {:?}, config: {:?}",
            schema,
            config
        );

        let schema = match schema {
            Schema::SchemaV1(s) => s,
        };
        let (cred_def_id, schema_id) = Self::make_credential_definition_id(
            origin_did,
            &schema.id,
            schema.seq_no,
            tag,
            signature_type,
        )?;

        let credential_schema = build_credential_schema(&schema.attr_names.0)?;
        let non_credential_schema = build_non_credential_schema()?;

        let (credential_public_key, credential_private_key, credential_key_correctness_proof) =
            CryptoIssuer::new_credential_def(
                &credential_schema,
                &non_credential_schema,
                config.support_revocation,
            )?;

        let credential_definition_value = CredentialDefinitionData {
            primary: credential_public_key.get_primary_key()?.try_clone()?,
            revocation: credential_public_key.get_revocation_key()?.clone(),
        };

        let credential_definition =
            CredentialDefinition::CredentialDefinitionV1(CredentialDefinitionV1 {
                id: cred_def_id,
                schema_id,
                signature_type,
                tag: tag.to_owned(),
                value: credential_definition_value,
            });

        trace!("new_credential_definition <<< credential_definition: {:?}, credential_private_key: {:?}, credential_key_correctness_proof: {:?}",
        credential_definition, secret!(&credential_private_key), credential_key_correctness_proof);

        Ok((
            credential_definition,
            credential_private_key,
            credential_key_correctness_proof,
        ))
    }

    pub fn make_revocation_registry_id(
        origin_did: &DidValue,
        cred_def: &CredentialDefinition,
        tag: &str,
        rev_reg_type: RegistryType,
    ) -> IndyResult<RevocationRegistryId> {
        let cred_def = match cred_def {
            CredentialDefinition::CredentialDefinitionV1(c) => c,
        };

        let origin_did = match (origin_did.get_method(), cred_def.id.get_method()) {
            (None, Some(_)) => {
                return Err(input_err("Cannot use an unqualified Origin DID with a fully qualified Credential Definition ID"));
            }
            (Some(_), None) => {
                return Err(input_err("Cannot use a fully qualified Origin DID with an unqualified Credential Definition ID"));
            }
            _ => origin_did,
        };

        Ok(RevocationRegistryId::new(
            &origin_did,
            &cred_def.id,
            &rev_reg_type.to_str(),
            tag,
        ))
    }

    pub fn new_revocation_registry<TW>(
        origin_did: &DidValue,
        cred_def: &CredentialDefinition,
        tag: &str,
        rev_reg_type: RegistryType,
        issuance_type: IssuanceType,
        max_cred_num: u32,
        tails_writer: &mut TW,
    ) -> IndyResult<(
        RevocationRegistryDefinition,
        RevocationRegistry,
        RevocationKeyPrivate,
    )>
    where
        TW: TailsWriter,
    {
        trace!("new_revocation_registry >>> origin_did: {:?}, cred_def: {:?}, tag: {:?}, max_cred_num: {:?}, rev_reg_type: {:?}, issuance_type: {:?}",
               origin_did, cred_def, tag, max_cred_num, rev_reg_type, issuance_type);

        let rev_reg_id =
            Self::make_revocation_registry_id(origin_did, cred_def, tag, rev_reg_type)?;

        let cred_def = match cred_def {
            CredentialDefinition::CredentialDefinitionV1(c) => c,
        };
        let credential_pub_key = cred_def.get_public_key()?;

        // NOTE: registry is created with issuance_by_default: false, then updated later
        // this avoids generating the tails twice and is significantly faster
        let (revoc_key_pub, revoc_key_priv, revoc_registry, mut rev_tails_generator) =
            CryptoIssuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)?;

        let rev_keys_pub = RevocationRegistryDefinitionValuePublicKeys {
            accum_key: revoc_key_pub,
        };

        let (tails_location, tails_hash) = tails_writer.write(&mut rev_tails_generator)?;

        let revoc_reg_def_value = RevocationRegistryDefinitionValue {
            max_cred_num,
            issuance_type,
            public_keys: rev_keys_pub,
            tails_location: tails_location.clone(),
            tails_hash,
        };

        let revoc_reg_def = RevocationRegistryDefinition::RevocationRegistryDefinitionV1(
            RevocationRegistryDefinitionV1 {
                id: rev_reg_id.clone(),
                revoc_def_type: rev_reg_type,
                tag: tag.to_string(),
                cred_def_id: cred_def.id.clone(),
                value: revoc_reg_def_value,
            },
        );

        let revoc_reg = RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 {
            value: revoc_registry,
        });

        // now update registry to reflect issuance-by-default
        let revoc_reg = if issuance_type == IssuanceType::ISSUANCE_BY_DEFAULT {
            let tails_reader = TailsFileReader::new(&tails_location);
            let issued = HashSet::from_iter((1..=max_cred_num).into_iter());
            let (reg, _delta) = Self::update_revocation_registry(
                &revoc_reg_def,
                &revoc_reg,
                issued,
                HashSet::new(),
                &tails_reader,
            )?;
            reg
        } else {
            revoc_reg
        };

        trace!("new_revocation_registry <<< revoc_reg_def: {:?}, revoc_reg: {:?}, revoc_key_priv: {:?}",
            revoc_reg_def, revoc_reg, secret!(&revoc_key_priv));

        Ok((revoc_reg_def, revoc_reg, revoc_key_priv))
    }

    pub fn update_revocation_registry(
        rev_reg_def: &RevocationRegistryDefinition,
        rev_reg: &RevocationRegistry,
        issued: HashSet<u32>,
        revoked: HashSet<u32>,
        tails_reader: &TailsReader,
    ) -> IndyResult<(RevocationRegistry, RevocationRegistryDelta)> {
        let rev_reg_def = match rev_reg_def {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => v1,
        };
        let mut rev_reg = match rev_reg {
            RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
        };
        let max_cred_num = rev_reg_def.value.max_cred_num;
        let delta = CryptoIssuer::update_revocation_registry(
            &mut rev_reg,
            max_cred_num,
            issued,
            revoked,
            tails_reader,
        )?;
        Ok((
            RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 { value: rev_reg }),
            RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
                value: delta,
            }),
        ))
    }

    pub fn new_credential_offer(
        schema_id: &SchemaId,
        cred_def: &CredentialDefinition,
        correctness_proof: &CredentialKeyCorrectnessProof,
    ) -> IndyResult<CredentialOffer> {
        trace!("new_credential_offer >>> cred_def: {:?}", cred_def);

        let nonce = new_nonce()?;

        let cred_def = match cred_def {
            CredentialDefinition::CredentialDefinitionV1(c) => c,
        };

        // FIXME why doesn't correctness proof implement clone?
        let key_correctness_proof = serde_json::from_value::<CredentialKeyCorrectnessProof>(
            serde_json::to_value(correctness_proof)?,
        )?;

        let credential_offer = CredentialOffer {
            schema_id: schema_id.clone(),
            cred_def_id: cred_def.id.clone(),
            key_correctness_proof,
            nonce,
            method_name: None,
        };

        trace!("new_credential_offer <<< result: {:?}", credential_offer);
        Ok(credential_offer)
    }

    pub fn new_credential(
        cred_def: &CredentialDefinition,
        cred_private_key: &CredentialPrivateKey,
        cred_offer: &CredentialOffer,
        cred_request: &CredentialRequest,
        cred_values: &CredentialValues,
        revocation_config: Option<CredentialRevocationConfig>,
    ) -> IndyResult<(
        Credential,
        Option<RevocationRegistry>,
        Option<RevocationRegistryDelta>,
    )> {
        trace!("new_credential >>> cred_def: {:?}, cred_private_key: {:?}, cred_offer.nonce: {:?}, cred_request: {:?},\
               cred_values: {:?}, revocation_config: {:?}",
               cred_def, secret!(&cred_private_key), &cred_offer.nonce, &cred_request, secret!(&cred_values), revocation_config,
               );

        let cred_public_key = match cred_def {
            CredentialDefinition::CredentialDefinitionV1(cd) => cd.get_public_key()?,
        };
        let credential_values = build_credential_values(&cred_values.0, None)?;

        let (
            credential_signature,
            signature_correctness_proof,
            rev_reg_id,
            rev_reg,
            rev_reg_delta,
            witness,
        ) = match revocation_config {
            Some(revocation) => {
                let (rev_reg_def, reg_reg_id) = match revocation.reg_def {
                    RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => {
                        (&v1.value, v1.id.clone())
                    }
                };
                let mut rev_reg = match revocation.registry {
                    RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
                };
                let (credential_signature, signature_correctness_proof, delta) =
                    CryptoIssuer::sign_credential_with_revoc(
                        &cred_request.prover_did.0,
                        &cred_request.blinded_ms,
                        &cred_request.blinded_ms_correctness_proof,
                        &cred_offer.nonce,
                        &cred_request.nonce,
                        &credential_values,
                        &cred_public_key,
                        &cred_private_key,
                        revocation.registry_idx,
                        rev_reg_def.max_cred_num,
                        rev_reg_def.issuance_type.to_bool(),
                        &mut rev_reg,
                        revocation.registry_key,
                        &revocation.tails_reader,
                    )?;

                let cred_rev_reg_id = match cred_offer.method_name.as_ref() {
                    Some(ref _method_name) => Some(reg_reg_id.to_unqualified()),
                    _ => Some(reg_reg_id.clone()),
                };
                let witness = {
                    let used = HashSet::new(); // FIXME HashSet::from_iter((0..revocation.registry_idx).into_iter());
                    let (by_default, issued, revoked) = match rev_reg_def.issuance_type {
                        IssuanceType::ISSUANCE_ON_DEMAND => (false, used, HashSet::new()),
                        IssuanceType::ISSUANCE_BY_DEFAULT => (true, HashSet::new(), used),
                    };

                    let rev_reg_delta = CryptoRevocationRegistryDelta::from_parts(
                        None, &rev_reg, &issued, &revoked,
                    );
                    Witness::new(
                        revocation.registry_idx,
                        rev_reg_def.max_cred_num,
                        by_default,
                        &rev_reg_delta,
                        &revocation.tails_reader,
                    )?
                };
                (
                    credential_signature,
                    signature_correctness_proof,
                    cred_rev_reg_id,
                    Some(rev_reg),
                    delta,
                    Some(witness),
                )
            }
            None => {
                let (signature, correctness_proof) = CryptoIssuer::sign_credential(
                    &cred_request.prover_did.0,
                    &cred_request.blinded_ms,
                    &cred_request.blinded_ms_correctness_proof,
                    &cred_offer.nonce,
                    &cred_request.nonce,
                    &credential_values,
                    &cred_public_key,
                    &cred_private_key,
                )?;
                (signature, correctness_proof, None, None, None, None)
            }
        };

        let credential = Credential {
            schema_id: cred_offer.schema_id.clone(),
            cred_def_id: cred_offer.cred_def_id.clone(),
            rev_reg_id,
            values: cred_values.clone(),
            signature: credential_signature,
            signature_correctness_proof,
            rev_reg: rev_reg.clone(),
            witness,
        };

        let rev_reg = rev_reg.map(|reg| {
            RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 { value: reg })
        });
        let rev_reg_delta = rev_reg_delta.map(|delta| {
            RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
                value: delta,
            })
        });

        trace!(
            "new_credential <<< credential {:?}, rev_reg_delta {:?}",
            secret!(&credential),
            rev_reg_delta
        );

        Ok((credential, rev_reg, rev_reg_delta))
    }

    pub fn revoke(
        &self,
        rev_reg: &RevocationRegistry,
        max_cred_num: u32,
        rev_idx: u32,
        tails_reader: &TailsReader,
    ) -> IndyResult<RevocationRegistryDelta> {
        trace!(
            "revoke >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
            rev_reg,
            max_cred_num,
            secret!(&rev_idx)
        );

        let mut rev_reg = match rev_reg {
            RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
        };
        let rev_reg_delta =
            CryptoIssuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, tails_reader)?;

        let delta = RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
            value: rev_reg_delta,
        });
        trace!("revoke <<< rev_reg_delta {:?}", delta);

        Ok(delta)
    }

    #[allow(dead_code)]
    pub fn recovery(
        &self,
        rev_reg: &RevocationRegistry,
        max_cred_num: u32,
        rev_idx: u32,
        tails_reader: &TailsReader,
    ) -> IndyResult<RevocationRegistryDelta> {
        trace!(
            "recovery >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
            rev_reg,
            max_cred_num,
            secret!(&rev_idx)
        );

        let mut rev_reg = match rev_reg {
            RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
        };
        let rev_reg_delta =
            CryptoIssuer::recovery_credential(&mut rev_reg, max_cred_num, rev_idx, tails_reader)?;

        let delta = RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
            value: rev_reg_delta,
        });
        trace!("recovery <<< rev_reg_delta {:?}", delta);

        Ok(delta)
    }
}

pub struct CredentialRevocationConfig<'a> {
    pub reg_def: &'a RevocationRegistryDefinition,
    pub registry: &'a RevocationRegistry,
    pub registry_key: &'a RevocationKeyPrivate,
    pub registry_idx: u32,
    pub tails_reader: TailsReader,
}

impl<'a> std::fmt::Debug for CredentialRevocationConfig<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CredentialRevocationConfig {{ reg_def: {:?}, registry: {:?}, key: {:?}, idx: {}, reader: {:?} }}",
            self.reg_def,
            self.registry,
            secret!(self.registry_key),
            secret!(self.registry_idx),
            self.tails_reader,
        )
    }
}

/*#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_credential_definition() {
        let attrs = r#"["one", "two"]"#;
        let attr_names = serde_json::from_str::<AttributeNames>(attrs).unwrap();
        Issuer::new_credential_definition(&attr_names, false).unwrap();
    }
}
*/
