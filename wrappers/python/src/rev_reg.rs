use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use std::collections::HashSet;
use std::iter::FromIterator;
use std::str::FromStr;

use indy_credx::common::did::DidValue;
use indy_credx::domain::revocation_registry::RevocationRegistry;
use indy_credx::domain::revocation_registry_definition::{
    IssuanceType, RegistryType, RevocationRegistryDefinition,
};
use indy_credx::domain::revocation_registry_delta::RevocationRegistryDelta;
use indy_credx::domain::revocation_state::RevocationState;
use indy_credx::services::issuer::Issuer;
use indy_credx::services::prover::Prover;
use indy_credx::services::tails::{TailsFileReader, TailsFileWriter};
use indy_credx::services::RevocationKeyPrivate;
use indy_credx::utils::validation::Validatable;

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

    #[getter]
    pub fn tails_hash(&self) -> PyResult<String> {
        match &self.inner {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(ref v1) => {
                Ok(v1.value.tails_hash.clone())
            }
        }
    }

    #[getter]
    pub fn tails_location(&self) -> PyResult<String> {
        match &self.inner {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(ref v1) => {
                Ok(v1.value.tails_location.clone())
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

#[pyclass(name=RevocationPrivateKey)]
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

#[pyclass(name=RevocationRegistryDelta)]
#[serde(transparent)]
#[derive(Serialize, Deserialize)]
pub struct PyRevocationRegistryDelta {
    pub inner: RevocationRegistryDelta,
}

#[pymethods]
impl PyRevocationRegistryDelta {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<RevocationRegistryDelta>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing revocation registry delta JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyRevocationRegistryDelta {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("RevocationRegistryDelta({:p})", self))
    }
}

impl From<RevocationRegistryDelta> for PyRevocationRegistryDelta {
    fn from(value: RevocationRegistryDelta) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyRevocationRegistryDelta {
    type Target = RevocationRegistryDelta;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyclass(name=RevocationState)]
#[serde(transparent)]
#[derive(Serialize, Deserialize)]
pub struct PyRevocationState {
    pub inner: RevocationState,
}

#[pymethods]
impl PyRevocationState {
    #[getter]
    pub fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<RevocationState>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing revocation state JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).map_py_err()?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyRevocationState {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("RevocationState({})", self.timestamp()))
    }
}

impl From<RevocationState> for PyRevocationState {
    fn from(value: RevocationState) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyRevocationState {
    type Target = RevocationState;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyfunction]
/// Creates a new revocation registry
fn create_revocation_registry(
    py: Python,
    origin_did: String,
    cred_def: PyAcceptJsonArg<PyCredentialDefinition>,
    rev_reg_type: String,
    tag: Option<String>,
    max_cred_num: u32,
    issuance_type: Option<String>,
    tails_dir_path: Option<String>,
) -> PyResult<(
    PyRevocationRegistryDefinition,
    PyRevocationRegistry,
    PyRevocationPrivateKey,
)> {
    let origin_did = DidValue(origin_did);
    origin_did.validate().map_py_err()?;
    let rev_reg_type = RegistryType::from_str(rev_reg_type.as_str()).map_py_err()?;
    let issuance_type = issuance_type
        .map(|it| IssuanceType::from_str(it.as_str()))
        .transpose()
        .map_py_err()?
        .unwrap_or(IssuanceType::ISSUANCE_BY_DEFAULT);
    let tag = tag.unwrap_or_else(|| "default".to_owned()); // FIXME
    let mut tails_writer = TailsFileWriter::new(tails_dir_path);
    let (rev_reg_def, rev_reg, rev_private_key) = py
        .allow_threads(move || {
            Issuer::new_revocation_registry(
                &origin_did,
                &cred_def,
                tag.as_str(),
                rev_reg_type,
                issuance_type,
                max_cred_num,
                &mut tails_writer,
            )
        })
        .map_py_err_msg(|| "Error creating revocation registry")?; // FIXME combine error
    Ok((
        PyRevocationRegistryDefinition::from(rev_reg_def),
        PyRevocationRegistry::from(rev_reg),
        PyRevocationPrivateKey::embed_json(py, &rev_private_key)?,
    ))
}

#[pyfunction]
/// Creates or update a revocation state
fn create_or_update_revocation_state(
    py: Python,
    revoc_reg_def: PyAcceptJsonArg<PyRevocationRegistryDefinition>,
    rev_reg_delta: PyAcceptJsonArg<PyRevocationRegistryDelta>,
    rev_reg_idx: u32,
    timestamp: u64,
    tails_file_path: String,
    rev_state: Option<PyAcceptJsonArg<PyRevocationState>>,
) -> PyResult<PyRevocationState> {
    let rev_state = rev_state.map(|state| state.clone());
    let rev_state = py
        .allow_threads(move || {
            Prover::create_or_update_revocation_state(
                TailsFileReader::new(tails_file_path.as_str()),
                &revoc_reg_def,
                &rev_reg_delta,
                rev_reg_idx,
                timestamp,
                rev_state,
            )
        })
        .map_py_err()?;
    Ok(PyRevocationState::from(rev_state))
}

#[pyfunction]
/// Update an existing revocation registry
fn update_revocation_registry(
    py: Python,
    rev_reg_def: PyAcceptJsonArg<PyRevocationRegistryDefinition>,
    rev_reg: PyAcceptJsonArg<PyRevocationRegistry>,
    issued: Option<Vec<u32>>,
    revoked: Option<Vec<u32>>,
    tails_file_path: String,
) -> PyResult<(PyRevocationRegistry, PyRevocationRegistryDelta)> {
    let (rev_reg, rev_reg_delta) = py
        .allow_threads(move || {
            let issued = HashSet::from_iter(issued.unwrap_or_else(|| vec![]).into_iter());
            let revoked = HashSet::from_iter(revoked.unwrap_or_else(|| vec![]).into_iter());
            let tails_reader = TailsFileReader::new(tails_file_path.as_str());
            Issuer::update_revocation_registry(
                &rev_reg_def,
                &rev_reg,
                issued,
                revoked,
                &tails_reader,
            )
        })
        .map_py_err_msg(|| "Error updating revocation registry")?; // FIXME combine error
    Ok((
        PyRevocationRegistry::from(rev_reg),
        PyRevocationRegistryDelta::from(rev_reg_delta),
    ))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_revocation_registry))?;
    m.add_wrapped(wrap_pyfunction!(create_or_update_revocation_state))?;
    m.add_wrapped(wrap_pyfunction!(update_revocation_registry))?;
    m.add_class::<PyRevocationRegistry>()?;
    m.add_class::<PyRevocationRegistryDefinition>()?;
    m.add_class::<PyRevocationPrivateKey>()?;
    Ok(())
}
