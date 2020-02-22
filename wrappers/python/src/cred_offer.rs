use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::domain::credential_offer::CredentialOffer;
use indy_credx::services::issuer::Issuer;

use crate::cred_def::{PyCredentialDefinition, PyCredentialKeyCorrectnessProof};
use crate::error::PyIndyResult;

#[pyclass(name=CredentialOffer)]
pub struct PyCredentialOffer {
    pub inner: CredentialOffer,
}

#[pymethods]
impl PyCredentialOffer {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<CredentialOffer>(&json.to_string()?)
            .map_py_err_msg("Error parsing credential offer JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyCredentialOffer {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("CredentialOffer({:p})", self))
    }
}

#[pyfunction]
/// Creates a new credential offer
fn create_credential_offer(
    cred_def: &PyCredentialDefinition,
    correctness_proof: &PyCredentialKeyCorrectnessProof,
) -> PyResult<PyCredentialOffer> {
    let offer =
        Issuer::new_credential_offer(&cred_def.inner, &correctness_proof.inner).map_py_err()?;
    Ok(PyCredentialOffer { inner: offer })
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_credential_offer))?;
    m.add_class::<PyCredentialOffer>()?;
    Ok(())
}
