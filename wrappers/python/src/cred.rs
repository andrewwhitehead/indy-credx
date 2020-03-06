use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::domain::credential::{Credential, CredentialValues};
use indy_credx::services as Services;
use indy_credx::services::issuer::Issuer;
use indy_credx::services::prover::Prover;

use crate::buffer::PySafeBuffer;
use crate::cred_def::{PyCredentialDefinition, PyCredentialPrivateKey};
use crate::cred_offer::PyCredentialOffer;
use crate::cred_request::{PyCredentialRequest, PyCredentialRequestMetadata};
use crate::error::PyIndyResult;
use crate::helpers::{PyAcceptBufferArg, PyAcceptJsonArg, PyJsonSafeBuffer};
use crate::master_secret::PyMasterSecret;

#[pyclass(name=Credential)]
pub struct PyCredential {
    pub inner: Py<PySafeBuffer>,
}

#[pymethods]
impl PyCredential {
    #[getter]
    pub fn buffer(&self, py: Python) -> PyResult<PyObject> {
        Ok(self.inner.to_object(py))
    }

    #[classmethod]
    pub fn from_json(_cls: &PyType, py: Python, json: &PyString) -> PyResult<Self> {
        <Self as PyJsonSafeBuffer>::from_json_insecure(py, json)
    }

    pub fn to_json(&self, py: Python) -> PyResult<String> {
        <Self as PyJsonSafeBuffer>::to_json_insecure(self, py)
    }
}

#[pyproto]
impl PyObjectProtocol for PyCredential {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Credential({:p})", self))
    }
}

impl From<Py<PySafeBuffer>> for PyCredential {
    fn from(inner: Py<PySafeBuffer>) -> Self {
        Self { inner }
    }
}

impl PyJsonSafeBuffer for PyCredential {
    type Inner = Credential;
    fn buffer(&self, py: Python) -> &PySafeBuffer {
        self.inner.as_ref(py)
    }
}

#[pyfunction]
/// Creates a new credential
pub fn create_credential(
    py: Python,
    cred_def: PyAcceptJsonArg<PyCredentialDefinition>,
    cred_private_key: PyAcceptBufferArg<PyCredentialPrivateKey>,
    cred_offer: PyAcceptJsonArg<PyCredentialOffer>,
    cred_request: PyAcceptJsonArg<PyCredentialRequest>,
    cred_values: String,
    /* ^ FIXME add helper to prepare credential values (w/attribute encoding),
    and pass in safe buffer here */
    // , revocation config
) -> PyResult<PyCredential> {
    let cred_values =
        serde_json::from_str::<CredentialValues>(cred_values.as_ref()).map_py_err()?;
    let cred_private_key = &cred_private_key.extract_json(py)?;
    let (credential, _delta) = py
        .allow_threads(move || {
            Issuer::new_credential::<Services::NullTailsAccessor>(
                &cred_def,
                &cred_private_key,
                &cred_offer,
                &cred_request,
                &cred_values,
                None,
            )
        })
        .map_py_err()?;
    Ok(PyCredential::embed_json(py, &credential)?)
}

#[pyfunction]
/// Process a received credential
pub fn process_credential(
    py: Python,
    cred: PyAcceptBufferArg<PyCredential>,
    cred_req_meta: PyAcceptJsonArg<PyCredentialRequestMetadata>,
    master_secret: PyAcceptBufferArg<PyMasterSecret>,
    cred_def: PyAcceptJsonArg<PyCredentialDefinition>,
    // rev_reg_def: &PyRevocationRegistryDefinition,
) -> PyResult<PyCredential> {
    let mut credential = cred.extract_json(py)?;
    let master_secret = master_secret.extract_json(py)?;
    let credential = py
        .allow_threads(move || {
            Prover::process_credential(
                &mut credential,
                &cred_req_meta.inner,
                &master_secret,
                &cred_def.inner,
                None,
            )
            .and(Ok(credential))
        })
        .map_py_err()?;
    Ok(PyCredential::embed_json(py, &credential)?)
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_credential))?;
    m.add_wrapped(wrap_pyfunction!(process_credential))?;
    m.add_class::<PyCredential>()?;
    Ok(())
}
