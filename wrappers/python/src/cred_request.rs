use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyTuple, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::common::did::DidValue;
use indy_credx::domain::credential_request::{CredentialRequest, CredentialRequestMetadata};
use indy_credx::services::prover::Prover;
use indy_credx::utils::validation::Validatable;

use crate::cred_def::PyCredentialDefinition;
use crate::cred_offer::PyCredentialOffer;
use crate::error::PyIndyResult;
use crate::helpers::{PyAcceptBufferArg, PyAcceptJsonArg, PyJsonSafeBuffer};
use crate::master_secret::PyMasterSecret;

#[pyclass(name=CredentialRequest)]
#[serde(transparent)]
#[derive(Serialize, Deserialize)]
pub struct PyCredentialRequest {
    pub inner: CredentialRequest,
}

#[pymethods]
impl PyCredentialRequest {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<CredentialRequest>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing credential request JSON")?;
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

impl From<CredentialRequest> for PyCredentialRequest {
    fn from(value: CredentialRequest) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyCredentialRequest {
    type Target = CredentialRequest;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyclass(name=CredentialRequest)]
#[serde(transparent)]
#[derive(Serialize, Deserialize)]
pub struct PyCredentialRequestMetadata {
    pub inner: CredentialRequestMetadata,
}

#[pymethods]
impl PyCredentialRequestMetadata {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<CredentialRequestMetadata>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing credential request metadata JSON")?;
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

impl From<CredentialRequestMetadata> for PyCredentialRequestMetadata {
    fn from(value: CredentialRequestMetadata) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyCredentialRequestMetadata {
    type Target = CredentialRequestMetadata;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyfunction]
/// Creates a new credential request
fn create_credential_request(
    py: Python,
    prover_did: String,
    cred_def: PyAcceptJsonArg<PyCredentialDefinition>,
    master_secret: PyAcceptBufferArg<PyMasterSecret>,
    master_secret_id: String,
    cred_offer: PyAcceptJsonArg<PyCredentialOffer>,
) -> PyResult<PyObject> {
    let prover_did = DidValue(prover_did);
    prover_did.validate().map_py_err()?;
    let master_secret = &master_secret.extract_json(py)?;

    let (request, metadata) = py
        .allow_threads(move || {
            Prover::new_credential_request(
                &prover_did,
                &cred_def,
                &master_secret,
                master_secret_id.as_str(),
                &cred_offer,
            )
        })
        .map_py_err()?;
    let args: &[PyObject; 2] = &[
        PyCredentialRequest::from(request).into_py(py),
        PyCredentialRequestMetadata::from(metadata).into_py(py),
    ];
    Ok(PyTuple::new(py, args).to_object(py))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_credential_request))?;
    m.add_class::<PyCredentialRequest>()?;
    m.add_class::<PyCredentialRequestMetadata>()?;
    Ok(())
}
