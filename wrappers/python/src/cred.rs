use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::domain::credential::{Credential, CredentialValues};
use indy_credx::services as Services;
use indy_credx::services::issuer::Issuer;

// use crate::buffer::PySafeBuffer;
use crate::cred_def::{PyCredentialDefinition, PyCredentialPrivateKey};
use crate::cred_offer::PyCredentialOffer;
use crate::cred_request::PyCredentialRequest;
use crate::error::PyIndyResult;

#[pyclass(name=CredentialDefinition)]
pub struct PyCredential {
    // FIXME wrap in a safe buffer
    pub inner: Credential,
}

#[pymethods]
impl PyCredential {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<Credential>(&json.to_string()?)
            .map_py_err_msg("Error parsing credential JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyCredential {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Credential({:p})", self))
    }
}

#[pyfunction]
/// Creates a new credential
pub fn create_credential(
    py: Python,
    cred_def: &PyCredentialDefinition,
    cred_private_key: &PyCredentialPrivateKey,
    cred_offer: &PyCredentialOffer,
    cred_request: &PyCredentialRequest,
    cred_values: &PyString,
    //revocation config
) -> PyResult<PyCredential> {
    let cred_values = cred_values.to_string()?;
    let cred_values =
        serde_json::from_str::<CredentialValues>(cred_values.as_ref()).map_py_err()?;
    let cred_private_key = &cred_private_key.extract(py)?;
    let (credential, _delta) = py
        .allow_threads(move || {
            Issuer::new_credential::<Services::NullTailsAccessor>(
                &cred_def.inner,
                &cred_private_key,
                &cred_offer.inner,
                &cred_request.inner,
                &cred_values,
                None,
            )
        })
        .map_py_err()?;
    Ok(PyCredential { inner: credential })
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_credential))?;
    m.add_class::<PyCredential>()?;
    Ok(())
}
