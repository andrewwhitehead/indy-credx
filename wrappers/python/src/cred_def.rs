use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyTuple, PyType};
use pyo3::wrap_pyfunction;

use crate::buffer::PySafeBuffer;
use crate::error::PyIndyResult;
use crate::schema::PySchema;
use indy_credx::common::did::DidValue;
use indy_credx::domain::credential_definition::{CredentialDefinition, CredentialDefinitionConfig};
use indy_credx::services as Services;
use indy_credx::services::issuer::Issuer;

#[pyclass(name=CredentialDefinition)]
pub struct PyCredentialDefinition {
    inner: CredentialDefinition,
}

#[pymethods]
impl PyCredentialDefinition {
    #[getter]
    pub fn cred_def_id(&self) -> PyResult<String> {
        match &self.inner {
            CredentialDefinition::CredentialDefinitionV1(c) => Ok(c.id.to_string()),
        }
    }

    #[getter]
    pub fn schema_id(&self) -> PyResult<String> {
        match &self.inner {
            CredentialDefinition::CredentialDefinitionV1(c) => Ok(c.schema_id.to_string()),
        }
    }

    #[getter]
    pub fn signature_type(&self) -> PyResult<String> {
        match &self.inner {
            CredentialDefinition::CredentialDefinitionV1(c) => {
                Ok(c.signature_type.to_str().to_string())
            }
        }
    }

    #[getter]
    pub fn tag(&self) -> PyResult<String> {
        match &self.inner {
            CredentialDefinition::CredentialDefinitionV1(c) => Ok(c.tag.to_string()),
        }
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }

    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner =
            serde_json::from_str::<CredentialDefinition>(&json.to_string()?).map_py_err()?;
        Ok(Self { inner })
    }
}

#[pyproto]
impl PyObjectProtocol for PyCredentialDefinition {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("CredentialDefinition({})", self.cred_def_id()?))
    }
}

#[pyclass(name=CredentialKeyCorrectnessProof)]
pub struct PyCredentialKeyCorrectnessProof {
    inner: Services::CredentialKeyCorrectnessProof,
}

#[pymethods]
impl PyCredentialKeyCorrectnessProof {
    fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }

    #[classmethod]
    fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<Services::CredentialKeyCorrectnessProof>(
            &json.to_string_lossy(),
        )
        .map_py_err()?;
        Ok(Self { inner })
    }
}

#[pyproto]
impl PyObjectProtocol for PyCredentialKeyCorrectnessProof {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "CredentialKeyCorrectnessProof({})",
            self.to_json()?
        ))
    }
}

#[pyfunction]
/// Creates a new credential definition
pub fn create_credential_definition(
    py: Python,
    origin_did: &PyString,
    schema: &PySchema,
    tag: Option<&PyString>,
) -> PyResult<PyObject> {
    let origin_did = origin_did.to_string()?.to_string();
    let tag = if let Some(tag) = tag {
        String::clone(&tag.to_string()?.to_string())
    } else {
        "default".to_string()
    };
    let config = CredentialDefinitionConfig {
        signature_type: None,
        support_revocation: false,
    };
    let (cred_def, private_key, correctness_proof) = py
        .allow_threads(move || {
            Issuer::new_credential_definition(
                &DidValue(origin_did),
                &schema.inner,
                tag.as_str(),
                config,
            )
        })
        .map_py_err()?;
    let key_json = serde_json::to_vec(&private_key).map_py_err()?;
    let args: &[PyObject; 3] = &[
        PyCredentialDefinition { inner: cred_def }.into_py(py),
        PySafeBuffer::new(key_json).into_py(py),
        PyCredentialKeyCorrectnessProof {
            inner: correctness_proof,
        }
        .into_py(py),
    ];
    Ok(PyTuple::new(py, args).to_object(py))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_credential_definition))?;
    m.add_class::<PyCredentialDefinition>()?;
    m.add_class::<PyCredentialKeyCorrectnessProof>()?;
    Ok(())
}
