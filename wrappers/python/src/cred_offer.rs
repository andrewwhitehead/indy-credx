use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::domain::credential_offer::CredentialOffer;
use indy_credx::identifiers::schema::SchemaId;
use indy_credx::services::issuer::Issuer;
use indy_credx::utils::validation::Validatable;

use crate::cred_def::{PyCredentialDefinition, PyCredentialKeyCorrectnessProof};
use crate::error::PyIndyResult;
use crate::helpers::PyAcceptJsonArg;

#[pyclass(name=CredentialOffer)]
#[serde(transparent)]
#[derive(Serialize, Deserialize)]
pub struct PyCredentialOffer {
    pub inner: CredentialOffer,
}

#[pymethods]
impl PyCredentialOffer {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<CredentialOffer>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing credential offer JSON")?;
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

impl From<CredentialOffer> for PyCredentialOffer {
    fn from(value: CredentialOffer) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyCredentialOffer {
    type Target = CredentialOffer;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyfunction]
/// Creates a new credential offer
fn create_credential_offer(
    schema_id: String,
    cred_def: PyAcceptJsonArg<PyCredentialDefinition>,
    correctness_proof: PyAcceptJsonArg<PyCredentialKeyCorrectnessProof>,
) -> PyResult<PyCredentialOffer> {
    let schema_id = SchemaId(schema_id);
    schema_id.validate().map_py_err()?;
    let offer = Issuer::new_credential_offer(&schema_id, &cred_def.inner, &correctness_proof.inner)
        .map_py_err()?;
    Ok(PyCredentialOffer::from(offer))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_credential_offer))?;
    m.add_class::<PyCredentialOffer>()?;
    Ok(())
}
