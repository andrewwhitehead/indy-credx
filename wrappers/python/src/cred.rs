use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::PyString;
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
use crate::master_secret::PyMasterSecret;

#[pyclass(name=CredentialDefinition)]
pub struct PyCredential {
    pub inner: Py<PySafeBuffer>,
}

#[pymethods]
impl PyCredential {
    #[getter]
    pub fn buffer(&self, py: Python) -> PyResult<PyObject> {
        Ok(self.inner.to_object(py))
    }

    /*#[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<Credential>(&json.to_string()?)
            .map_py_err_msg("Error parsing credential JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }*/
}

#[pyproto]
impl PyObjectProtocol for PyCredential {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Credential({:p})", self))
    }
}

impl PyCredential {
    pub fn embed_json(py: Python, value: &Credential) -> PyResult<Self> {
        Ok(Self {
            inner: Py::new(py, PySafeBuffer::serialize(value)?)?,
        })
    }

    pub fn extract_json(&self, py: Python) -> PyResult<Credential> {
        self.inner.as_ref(py).deserialize()
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
    /* ^ FIXME add helper to prepare credential values (w/attribute encoding),
    pass in safe buffer here */
    // , revocation config
) -> PyResult<PyCredential> {
    let cred_values = cred_values.to_string()?;
    let cred_values =
        serde_json::from_str::<CredentialValues>(cred_values.as_ref()).map_py_err()?;
    let cred_private_key = &cred_private_key.extract_json(py)?;
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
    let credential_json = serde_json::to_vec(&credential).map_py_err()?;
    Ok(PyCredential {
        inner: Py::new(py, PySafeBuffer::new(credential_json))?,
    })
}

#[pyfunction]
/// Process a received credential
pub fn process_credential(
    py: Python,
    cred: &PyCredential,
    cred_req_meta: &PyCredentialRequestMetadata,
    master_secret: &PyMasterSecret,
    cred_def: &PyCredentialDefinition,
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
