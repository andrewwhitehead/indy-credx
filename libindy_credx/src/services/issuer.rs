use tempfile;

use std::io::Write;
use std::path::PathBuf;

use crate::common::did::DidValue;
use crate::common::error::prelude::*;
use crate::domain::credential::{Credential, CredentialValues};
use crate::domain::credential_definition::{
    CredentialDefinition, CredentialDefinitionConfig, CredentialDefinitionData,
    CredentialDefinitionId, CredentialDefinitionV1, SignatureType,
};
use crate::domain::credential_offer::CredentialOffer;
use crate::domain::credential_request::CredentialRequest;
use crate::domain::revocation_registry::{RevocationRegistry, RevocationRegistryV1};
use crate::domain::revocation_registry_definition::{
    IssuanceType, RegistryType, RevocationRegistryDefinition, RevocationRegistryDefinitionV1,
    RevocationRegistryDefinitionValue, RevocationRegistryDefinitionValuePublicKeys,
    RevocationRegistryId,
};
use crate::domain::revocation_registry_delta::{
    RevocationRegistryDelta, RevocationRegistryDeltaV1,
};
use crate::domain::schema::{AttributeNames, Schema, SchemaId, SchemaV1};
use crate::services::helpers::*;
use crate::utils::base58::ToBase58;
use crate::utils::validation::Validatable;

use super::{
    new_nonce, CredentialKeyCorrectnessProof, CredentialPrivateKey, CryptoIssuer,
    CryptoRevocationRegistry, Digest, RevocationKeyPrivate, RevocationTailsAccessor,
    RevocationTailsGenerator, Sha256,
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

    pub fn new_credential_definition(
        origin_did: &DidValue,
        schema: &Schema,
        tag: &str,
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
        let credential_schema = build_credential_schema(&schema.attr_names.0)?;
        let non_credential_schema = build_non_credential_schema()?;

        let schema_id = match (origin_did.get_method(), schema.id.get_method()) {
            (None, Some(_)) => {
                return Err(input_err(
                    "Cannot use an unqualified Origin DID with fully qualified Schema ID",
                ));
            }
            (Some(prefix_), None) => schema.id.qualify(&prefix_),
            _ => schema.id.clone(),
        };
        let schema_seq_no_id = schema
            .seq_no
            .map(|n| SchemaId(n.to_string()))
            .unwrap_or(SchemaId(schema_id.0.clone()));

        let signature_type = config.signature_type.unwrap_or(SignatureType::CL);

        let cred_def_id = CredentialDefinitionId::new(
            origin_did,
            &schema_seq_no_id,
            &signature_type.to_str(),
            tag,
        );

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

    pub fn new_revocation_registry<TW>(
        origin_did: &DidValue,
        cred_def: &CredentialDefinition,
        tag: &str,
        max_cred_num: u32,
        tails_writer: &mut TW,
        rev_reg_type: Option<RegistryType>,
        issuance_type: Option<IssuanceType>,
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

        let cred_def = match cred_def {
            CredentialDefinition::CredentialDefinitionV1(c) => c,
        };
        let credential_pub_key = cred_def.get_public_key()?;

        let origin_did = match (origin_did.get_method(), cred_def.id.get_method()) {
            (None, Some(_)) => {
                return Err(input_err("Cannot use an unqualified Origin DID with a fully qualified Credential Definition ID"));
            }
            (Some(_), None) => {
                return Err(input_err("Cannot use a fully qualified Origin DID with an unqualified Credential Definition ID"));
            }
            _ => origin_did,
        };

        let rev_reg_type = rev_reg_type.unwrap_or(RegistryType::CL_ACCUM);
        let issuance_type = issuance_type.unwrap_or(IssuanceType::ISSUANCE_BY_DEFAULT);

        // FIXME
        // need a way to generate the ID ahead of time, so the caller can make sure
        // that ID hasn't been stored in the wallet already
        let rev_reg_id =
            RevocationRegistryId::new(&origin_did, &cred_def.id, &rev_reg_type.to_str(), tag);

        let (revoc_key_pub, revoc_key_priv, revoc_registry, mut rev_tails_generator) =
            CryptoIssuer::new_revocation_registry_def(
                &credential_pub_key,
                max_cred_num,
                issuance_type == IssuanceType::ISSUANCE_BY_DEFAULT,
            )?;

        let rev_keys_pub = RevocationRegistryDefinitionValuePublicKeys {
            accum_key: revoc_key_pub,
        };

        let (tails_location, tails_hash) = tails_writer.write(&mut rev_tails_generator)?;

        let revoc_reg_def_value = RevocationRegistryDefinitionValue {
            max_cred_num,
            issuance_type,
            public_keys: rev_keys_pub,
            tails_location,
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

        trace!("new_revocation_registry <<< revoc_reg_def: {:?}, revoc_reg: {:?}, revoc_key_priv: {:?}",
            revoc_reg_def, revoc_reg, secret!(&revoc_key_priv));

        Ok((revoc_reg_def, revoc_reg, revoc_key_priv))
    }

    pub fn new_credential_offer(
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
            schema_id: cred_def.schema_id.clone(),
            cred_def_id: cred_def.id.clone(),
            key_correctness_proof,
            nonce,
            method_name: None,
        };

        trace!("new_credential_offer <<< result: {:?}", credential_offer);
        Ok(credential_offer)
    }

    pub fn new_credential<RTA>(
        cred_def: &CredentialDefinition,
        cred_priv_key: &CredentialPrivateKey,
        cred_offer: &CredentialOffer,
        cred_request: &CredentialRequest,
        cred_values: &CredentialValues,
        revocation_config: Option<RevocationConfig<RTA>>,
    ) -> IndyResult<(Credential, Option<RevocationRegistryDelta>)>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!("new_credential >>> cred_def: {:?}, cred_priv_key: {:?}, cred_offer.nonce: {:?}, cred_request: {:?},\
               cred_values: {:?}, revocation_config: {:?}",
               cred_def, secret!(&cred_priv_key), &cred_offer.nonce, &cred_request, secret!(&cred_values), revocation_config,
               );

        let cred_pub_key = match cred_def {
            CredentialDefinition::CredentialDefinitionV1(cd) => cd.get_public_key()?,
        };
        let credential_values = build_credential_values(&cred_values.0, None)?;

        let (credential_signature, signature_correctness_proof, rev_reg_delta) =
            match revocation_config {
                Some(revocation) => CryptoIssuer::sign_credential_with_revoc(
                    &cred_request.prover_did.0,
                    &cred_request.blinded_ms,
                    &cred_request.blinded_ms_correctness_proof,
                    &cred_offer.nonce,
                    &cred_request.nonce,
                    &credential_values,
                    &cred_pub_key,
                    &cred_priv_key,
                    revocation.idx,
                    revocation.reg_def.value.max_cred_num,
                    revocation.reg_def.value.issuance_type.to_bool(),
                    revocation.registry,
                    revocation.private_key,
                    revocation.tails_accessor,
                )?,
                None => {
                    let (signature, correctness_proof) = CryptoIssuer::sign_credential(
                        &cred_request.prover_did.0,
                        &cred_request.blinded_ms,
                        &cred_request.blinded_ms_correctness_proof,
                        &cred_offer.nonce,
                        &cred_request.nonce,
                        &credential_values,
                        &cred_pub_key,
                        &cred_priv_key,
                    )?;
                    (signature, correctness_proof, None)
                }
            };

        let credential = Credential {
            schema_id: cred_offer.schema_id.clone(),
            cred_def_id: cred_offer.cred_def_id.clone(),
            rev_reg_id: None, //cred_rev_reg_id,
            values: cred_values.clone(),
            signature: credential_signature,
            signature_correctness_proof,
            rev_reg: None, // rev_reg.map(|r_reg| r_reg.value),
            witness: None, // FIXME
        };

        trace!(
            "new_credential <<< credential {:?}, rev_reg_delta {:?}",
            secret!(&credential),
            rev_reg_delta
        );

        Ok((credential, None))
    }

    pub fn revoke<RTA>(
        &self,
        rev_reg: &mut CryptoRevocationRegistry,
        max_cred_num: u32,
        rev_idx: u32,
        rev_tails_accessor: &RTA,
    ) -> IndyResult<RevocationRegistryDelta>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!(
            "revoke >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
            rev_reg,
            max_cred_num,
            secret!(&rev_idx)
        );

        let rev_reg_delta =
            CryptoIssuer::revoke_credential(rev_reg, max_cred_num, rev_idx, rev_tails_accessor)?;

        let delta = RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
            value: rev_reg_delta,
        });
        trace!("revoke <<< rev_reg_delta {:?}", delta);

        Ok(delta)
    }

    #[allow(dead_code)]
    pub fn recovery<RTA>(
        &self,
        rev_reg: &mut CryptoRevocationRegistry,
        max_cred_num: u32,
        rev_idx: u32,
        rev_tails_accessor: &RTA,
    ) -> IndyResult<RevocationRegistryDelta>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!(
            "recovery >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
            rev_reg,
            max_cred_num,
            secret!(&rev_idx)
        );

        let rev_reg_delta =
            CryptoIssuer::recovery_credential(rev_reg, max_cred_num, rev_idx, rev_tails_accessor)?;

        let delta = RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
            value: rev_reg_delta,
        });
        trace!("recovery <<< rev_reg_delta {:?}", delta);

        Ok(delta)
    }
}

pub struct RevocationConfig<'a, RTA>
where
    RTA: RevocationTailsAccessor,
{
    idx: u32,
    reg_def: &'a RevocationRegistryDefinitionV1,
    registry: &'a mut CryptoRevocationRegistry,
    private_key: &'a RevocationKeyPrivate,
    tails_accessor: &'a RTA,
}

impl<'a, RTA> std::fmt::Debug for RevocationConfig<'a, RTA>
where
    RTA: RevocationTailsAccessor,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RevocationConfig {{ idx: {}, reg_def: {:?}, registry: {:?}, private_key: {:?} }}",
            secret!(&self.idx),
            self.reg_def,
            self.registry,
            secret!(self.private_key)
        )
    }
}

pub trait TailsWriter {
    fn write(&mut self, generator: &mut RevocationTailsGenerator) -> IndyResult<(String, String)>;
}

pub struct TailsFileWriter {
    root_path: PathBuf,
}

impl TailsFileWriter {
    pub fn new(root_path: Option<String>) -> Self {
        Self {
            root_path: root_path
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir()),
        }
    }
}

impl TailsWriter for TailsFileWriter {
    fn write(&mut self, generator: &mut RevocationTailsGenerator) -> IndyResult<(String, String)> {
        let mut tempf = tempfile::NamedTempFile::new_in(self.root_path.clone())?;
        let file = tempf.as_file_mut();
        let mut hasher = Sha256::default();
        let version = &[0u8, 2u8];
        file.write(version)?;
        hasher.input(version);
        while let Some(tail) = generator.try_next()? {
            let tail_bytes = tail.to_bytes()?;
            file.write(tail_bytes.as_slice())?;
            hasher.input(tail_bytes);
        }
        let hash = hasher.result().to_base58();
        let path = tempf.path().with_file_name(hash.clone());
        if let Err(err) = tempf.persist_noclobber(hash.clone()) {
            return Err(err_msg(
                IndyErrorKind::IOError,
                format!("Error persisting tails file: {}", err),
            ));
        }
        Ok((path.to_string_lossy().into_owned(), hash))
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
