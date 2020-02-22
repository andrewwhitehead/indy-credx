pub mod helpers;
pub mod issuer;
pub mod prover;
pub mod verifier;

pub use crate::domain::credential_definition::CredentialDefinitionData;
pub use crate::domain::schema::AttributeNames;
pub use ursa::cl::issuer::Issuer as CryptoIssuer;
pub use ursa::cl::prover::Prover as CryptoProver;
pub use ursa::cl::verifier::Verifier as CryptoVerifier;
pub use ursa::cl::{
    new_nonce, BlindedCredentialSecrets, BlindedCredentialSecretsCorrectnessProof,
    CredentialKeyCorrectnessProof, CredentialPrivateKey, CredentialPublicKey,
    CredentialSecretsBlindingFactors, CredentialSignature, MasterSecret, Nonce,
    RevocationKeyPrivate, RevocationRegistry as CryptoRevocationRegistry,
    RevocationRegistryDelta as CryptoRevocationRegistryDelta, RevocationTailsAccessor,
    RevocationTailsGenerator, SignatureCorrectnessProof, SubProofRequest, Tail,
};

use ursa::errors::{err_msg as crypto_err_msg, UrsaCryptoError, UrsaCryptoErrorKind};
pub use ursa::hash::sha2::{Digest, Sha256};

pub struct NullTailsAccessor {}

impl RevocationTailsAccessor for NullTailsAccessor {
    fn access_tail(
        &self,
        _tail_id: u32,
        _accessor: &mut dyn FnMut(&Tail),
    ) -> Result<(), UrsaCryptoError> {
        Err(crypto_err_msg(
            UrsaCryptoErrorKind::InvalidState,
            "Null tails accessor cannot be accessed",
        ))
    }
}
