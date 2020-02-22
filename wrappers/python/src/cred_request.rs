use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyTuple, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::common::did::DidValue;
use indy_credx::domain::credential_request::{CredentialRequest, CredentialRequestMetadata};
use indy_credx::services::prover::Prover;

use crate::cred_def::PyCredentialDefinition;
use crate::cred_offer::PyCredentialOffer;
use crate::error::PyIndyResult;
use crate::master_secret::PyMasterSecret;

#[pyclass(name=CredentialRequest)]
pub struct PyCredentialRequest {
    pub inner: CredentialRequest,
}

#[pymethods]
impl PyCredentialRequest {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<CredentialRequest>(&json.to_string()?)
            .map_py_err_msg("Error parsing credential request JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyCredentialRequest {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("CredentialRequest({:p})", self))
    }
}

#[pyclass(name=CredentialRequest)]
pub struct PyCredentialRequestMetadata {
    pub inner: CredentialRequestMetadata,
}

#[pymethods]
impl PyCredentialRequestMetadata {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<CredentialRequestMetadata>(&json.to_string()?)
            .map_py_err_msg("Error parsing credential request metadata JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyCredentialRequestMetadata {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("CredentialRequestMetadata({:p})", self))
    }
}

#[pyfunction]
/// Creates a new credential request
fn create_credential_request(
    py: Python,
    prover_did: &PyString,
    cred_def: &PyCredentialDefinition,
    master_secret: &PyMasterSecret,
    master_secret_id: &PyString,
    cred_offer: &PyCredentialOffer,
) -> PyResult<PyObject> {
    let prover_did = prover_did.to_string()?.to_string();

    let master_secret_id = master_secret_id.to_string()?.to_string();
    let (request, metadata) = Prover::new_credential_request(
        &DidValue(prover_did),
        &cred_def.inner,
        &master_secret.extract(py)?,
        master_secret_id.as_str(),
        &cred_offer.inner,
    )
    .map_py_err()?;
    let args: &[PyObject; 2] = &[
        PyCredentialRequest { inner: request }.into_py(py),
        PyCredentialRequestMetadata { inner: metadata }.into_py(py),
    ];
    Ok(PyTuple::new(py, args).to_object(py))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_credential_request))?;
    m.add_class::<PyCredentialRequest>()?;
    m.add_class::<PyCredentialRequestMetadata>()?;
    Ok(())
}
