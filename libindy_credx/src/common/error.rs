use std::fmt;

use thiserror::Error;

use ursa::errors::{UrsaCryptoError, UrsaCryptoErrorKind};

pub mod prelude {
    pub use super::{err_msg, input_err, IndyError, IndyErrorKind, IndyResult, IndyResultExt};
}

#[derive(Debug, Error)]
pub struct IndyError {
    kind: IndyErrorKind,
    msg: Option<String>,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    // backtrace (when supported)
}

#[derive(Debug, Error, PartialEq)]
pub enum IndyErrorKind {
    // General errors
    #[error("Input error")]
    Input,
    #[error("IO error")]
    IOError,
    #[error("Invalid state")]
    InvalidState,
    #[error("Unexpected error")]
    Unexpected,
    // Credential/proof errors
    #[error("Credential revoked")]
    CredentialRevoked,
    #[error("Invalid revocation accumulator index")]
    InvalidUserRevocId,
    #[error("Proof rejected")]
    ProofRejected,
    #[error("Revocation registry full")]
    RevocationRegistryFull,
}

impl IndyError {
    pub fn new(
        kind: IndyErrorKind,
        msg: Option<String>,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self { kind, msg, source }
    }

    pub fn kind<'a>(&'a self) -> &'a IndyErrorKind {
        &self.kind
    }

    pub fn extra(&self) -> Option<String> {
        None
    }

    pub fn extend<D>(self, msg: D) -> IndyError
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        IndyError::new(self.kind, Some(msg.to_string()), self.source)
    }
}

impl fmt::Display for IndyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.kind, &self.msg) {
            (IndyErrorKind::Input, None) => write!(f, "{}", self.kind),
            (IndyErrorKind::Input, Some(msg)) => f.write_str(msg),
            (kind, None) => write!(f, "{}", kind),
            (kind, Some(msg)) => write!(f, "{}: {}", kind, msg),
        }?;
        if let Some(ref source) = self.source {
            write!(f, "\n{}", source)?;
        }
        Ok(())
    }
}

impl From<IndyError> for IndyErrorKind {
    fn from(error: IndyError) -> IndyErrorKind {
        error.kind
    }
}

impl From<IndyErrorKind> for IndyError {
    fn from(kind: IndyErrorKind) -> IndyError {
        IndyError::new(kind, None, None)
    }
}

impl From<std::io::Error> for IndyError {
    fn from(err: std::io::Error) -> Self {
        IndyError::new(IndyErrorKind::IOError, None, Some(Box::new(err)))
    }
}

impl From<UrsaCryptoError> for IndyError {
    fn from(err: UrsaCryptoError) -> Self {
        // let message = format!("Ursa Crypto Error: {}", Fail::iter_causes(&err).map(|e| e.to_string()).collect::<String>());
        let message = err.to_string();
        let kind = match err.kind() {
            UrsaCryptoErrorKind::InvalidState => IndyErrorKind::InvalidState,
            UrsaCryptoErrorKind::InvalidStructure => IndyErrorKind::Input,
            UrsaCryptoErrorKind::IOError => IndyErrorKind::IOError,
            UrsaCryptoErrorKind::InvalidRevocationAccumulatorIndex => {
                IndyErrorKind::InvalidUserRevocId
            }
            UrsaCryptoErrorKind::RevocationAccumulatorIsFull => {
                IndyErrorKind::RevocationRegistryFull
            }
            UrsaCryptoErrorKind::ProofRejected => IndyErrorKind::ProofRejected,
            UrsaCryptoErrorKind::CredentialRevoked => IndyErrorKind::CredentialRevoked,
            UrsaCryptoErrorKind::InvalidParam(_) => IndyErrorKind::Input,
        };
        IndyError::new(kind, Some(message), None)
    }
}

impl<M> From<(IndyErrorKind, M)> for IndyError
where
    M: fmt::Display + Send + Sync + 'static,
{
    fn from((kind, msg): (IndyErrorKind, M)) -> IndyError {
        IndyError::new(kind, Some(msg.to_string()), None)
    }
}

pub fn err_msg<M>(kind: IndyErrorKind, msg: M) -> IndyError
where
    M: fmt::Display + Send + Sync + 'static,
{
    (kind, msg.to_string()).into()
}

pub fn input_err<M>(msg: M) -> IndyError
where
    M: fmt::Display + Send + Sync + 'static,
{
    (IndyErrorKind::Input, msg.to_string()).into()
}

pub type IndyResult<T> = Result<T, IndyError>;

pub trait IndyResultExt<T, E> {
    fn map_err_string(self) -> Result<T, String>;
    fn map_input_err<F, M>(self, mapfn: F) -> IndyResult<T>
    where
        F: FnOnce() -> M,
        M: fmt::Display + Send + Sync + 'static;
    fn with_err_msg<M>(self, kind: IndyErrorKind, msg: M) -> IndyResult<T>
    where
        M: fmt::Display + Send + Sync + 'static;
    fn with_input_err<M>(self, msg: M) -> IndyResult<T>
    where
        M: fmt::Display + Send + Sync + 'static;
}

impl<T, E> IndyResultExt<T, E> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn map_err_string(self) -> Result<T, String> {
        self.map_err(|err| err.to_string())
    }

    fn map_input_err<F, M>(self, mapfn: F) -> IndyResult<T>
    where
        F: FnOnce() -> M,
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| {
            IndyError::new(
                IndyErrorKind::Input,
                Some(mapfn().to_string()),
                Some(Box::new(err)),
            )
        })
    }

    fn with_err_msg<M>(self, kind: IndyErrorKind, msg: M) -> IndyResult<T>
    where
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| IndyError::new(kind, Some(msg.to_string()), Some(Box::new(err))))
    }

    fn with_input_err<M>(self, msg: M) -> IndyResult<T>
    where
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| {
            IndyError::new(
                IndyErrorKind::Input,
                Some(msg.to_string()),
                Some(Box::new(err)),
            )
        })
    }
}
