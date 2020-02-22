#[macro_use]
extern crate log;

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod buffer;
mod cred_def;
mod schema;

/*#[pyfunction]
/// Creates a new credential
fn create_credential(
    py: Python,
    cred_def: &CredentialDefinitionData,

        &self,
        cred_def: &CredentialDefinition,
        cred_priv_key: &CredentialPrivateKey,
        cred_issuance_blinding_nonce: &Nonce,
        cred_request: &CredentialRequest,
        cred_values: &CredentialValues,
        rev_idx: Option<u32>,
        rev_reg_def: Option<&RevocationRegistryDefinitionV1>,
        rev_reg: Option<&mut RevocationRegistry>,
        rev_key_priv: Option<&RevocationKeyPrivate>,
        rev_tails_accessor: Option<&RTA>,
    ) -> IndyResult<(
        CredentialSignature,
        SignatureCorrectnessProof,
        Option<RevocationRegistryDelta>,

)*/

#[pyfunction]
/// Creates a new test buffer
fn create_test_buffer() -> PyResult<buffer::PySafeBuffer> {
    let buffer = buffer::PySafeBuffer::new(vec![b'a', b'b', b'c']);
    Ok(buffer)
}

/// Initializes the default logger
fn set_default_logger() {
    env_logger::init();
    debug!("Initialized default logger");
}

/// This module is a python module implemented in Rust.
#[pymodule]
fn indy_credx(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_test_buffer))?;
    cred_def::register(py, m)?;
    schema::register(py, m)?;

    m.add_class::<buffer::PySafeBuffer>()?;
    set_default_logger();

    Ok(())
}
