use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use std::str::FromStr;

use indy_credx::common::did::DidValue;
use indy_credx::domain::revocation_registry::RevocationRegistry;
use indy_credx::domain::revocation_registry_definition::{
    IssuanceType, RegistryType, RevocationRegistryDefinition,
};
use indy_credx::services::issuer::{Issuer, TailsFileWriter};
use indy_credx::services::RevocationKeyPrivate;

use crate::buffer::PySafeBuffer;
use crate::cred_def::PyCredentialDefinition;
use crate::error::PyIndyResult;
use crate::helpers::{PyAcceptJsonArg, PyJsonSafeBuffer};

#[pyclass(name=RevocationRegistry)]
#[serde(transparent)]
#[derive(Serialize, Deserialize)]
pub struct PyRevocationRegistry {
    pub inner: RevocationRegistry,
}

#[pymethods]
impl PyRevocationRegistry {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<RevocationRegistry>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing revocation registry JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyRevocationRegistry {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("RevocationRegistry({:p})", self))
    }
}

impl From<RevocationRegistry> for PyRevocationRegistry {
    fn from(value: RevocationRegistry) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyRevocationRegistry {
    type Target = RevocationRegistry;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyclass(name=RevocationRegistryDefinition)]
#[serde(transparent)]
#[derive(Serialize, Deserialize)]
pub struct PyRevocationRegistryDefinition {
    pub inner: RevocationRegistryDefinition,
}

#[pymethods]
impl PyRevocationRegistryDefinition {
    #[getter]
    pub fn rev_reg_def_id(&self) -> PyResult<String> {
        match &self.inner {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(def) => {
                Ok(def.id.to_string())
            }
        }
    }

    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<RevocationRegistryDefinition>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing revocation registry definition JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyRevocationRegistryDefinition {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "RevocationRegistryDefinition({})",
            self.rev_reg_def_id()?
        ))
    }
}

impl From<RevocationRegistryDefinition> for PyRevocationRegistryDefinition {
    fn from(value: RevocationRegistryDefinition) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyRevocationRegistryDefinition {
    type Target = RevocationRegistryDefinition;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyclass(name=RevocationKeyPrivate)]
pub struct PyRevocationPrivateKey {
    inner: Py<PySafeBuffer>,
}

#[pymethods]
impl PyRevocationPrivateKey {
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
impl PyObjectProtocol for PyRevocationPrivateKey {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("RevocationPrivateKey({:p})", self))
    }
}

impl From<Py<PySafeBuffer>> for PyRevocationPrivateKey {
    fn from(inner: Py<PySafeBuffer>) -> Self {
        Self { inner }
    }
}

impl PyJsonSafeBuffer for PyRevocationPrivateKey {
    type Inner = RevocationKeyPrivate;
    fn buffer(&self, py: Python) -> &PySafeBuffer {
        self.inner.as_ref(py)
    }
}

#[pyfunction]
/// Creates a new revocation registry
fn create_revocation_registry(
    py: Python,
    origin_did: &PyString,
    cred_def: PyAcceptJsonArg<PyCredentialDefinition>,
    tag: Option<String>,
    max_cred_num: u32,
    rev_reg_type: Option<String>,
    issuance_type: Option<String>,
    // FIXME optional tails path
) -> PyResult<(
    PyRevocationRegistryDefinition,
    PyRevocationRegistry,
    PyRevocationPrivateKey,
)> {
    let origin_did = origin_did.to_string()?; // FIXME validate (and in other places)
    let rev_reg_type = rev_reg_type
        .map(|rt| RegistryType::from_str(rt.as_str()))
        .transpose()
        .map_py_err()?;
    let issuance_type = issuance_type
        .map(|rt| IssuanceType::from_str(rt.as_str()))
        .transpose()
        .map_py_err()?;
    let tag = tag.unwrap_or_else(|| "default".to_owned()); // FIXME
    let mut tails_writer = TailsFileWriter::new(None);
    let (rev_reg_def, rev_reg, rev_private_key) = Issuer::new_revocation_registry(
        &DidValue(origin_did.into_owned()),
        &cred_def,
        tag.as_str(),
        max_cred_num,
        &mut tails_writer,
        rev_reg_type,
        issuance_type,
    )
    .map_py_err_msg(|| "Error creating revocation registry")?; // FIXME combine error
    Ok((
        PyRevocationRegistryDefinition::from(rev_reg_def),
        PyRevocationRegistry::from(rev_reg),
        PyRevocationPrivateKey::embed_json(py, &rev_private_key)?,
    ))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_revocation_registry))?;
    m.add_class::<PyRevocationRegistry>()?;
    m.add_class::<PyRevocationRegistryDefinition>()?;
    m.add_class::<PyRevocationPrivateKey>()?;
    Ok(())
}
