use std::collections::HashMap;

use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::domain::credential_definition::CredentialDefinitionId;
use indy_credx::domain::proof::Proof;
use indy_credx::domain::proof_request::ProofRequest;
use indy_credx::domain::requested_credential::RequestedCredentials;
use indy_credx::domain::schema::SchemaId;
use indy_credx::services::prover::Prover;

use crate::buffer::PySafeBuffer;
use crate::cred::PyCredential;
use crate::cred_def::PyCredentialDefinition;
use crate::error::PyIndyResult;
use crate::helpers::{PyAcceptBufferArg, PyAcceptJsonArg, PyJsonArg, PyJsonSafeBuffer};
use crate::master_secret::PyMasterSecret;
use crate::schema::PySchema;

#[pyclass(name=Proof)]
pub struct PyProof {
    pub inner: Py<PySafeBuffer>,
}

#[pymethods]
impl PyProof {
    #[getter]
    pub fn buffer(&self, py: Python) -> PyResult<PyObject> {
        Ok(self.inner.to_object(py))
    }

    #[classmethod]
    pub fn from_json(_cls: &PyType, py: Python, json: &PyString) -> PyResult<Self> {
        <Self as PyJsonSafeBuffer>::from_json(py, json)
    }

    pub fn to_json(&self, py: Python) -> PyResult<String> {
        <Self as PyJsonSafeBuffer>::to_json(self, py)
    }
}

#[pyproto]
impl PyObjectProtocol for PyProof {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Proof({:p})", self))
    }
}

impl From<Py<PySafeBuffer>> for PyProof {
    fn from(inner: Py<PySafeBuffer>) -> Self {
        Self { inner }
    }
}

impl PyJsonSafeBuffer for PyProof {
    type Inner = Proof;
    fn buffer(&self, py: Python) -> &PySafeBuffer {
        self.inner.as_ref(py)
    }
}

#[pyclass(name=ProofRequest)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct PyProofRequest {
    pub inner: ProofRequest,
}

#[pymethods]
impl PyProofRequest {
    #[classmethod]
    pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
        let inner = serde_json::from_str::<ProofRequest>(&json.to_string()?)
            .map_py_err_msg(|| "Error parsing proof request JSON")?;
        Ok(Self { inner })
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner)
            .map_py_err_msg(|| "Error serializing proof request JSON")?)
    }
}

#[pyproto]
impl PyObjectProtocol for PyProofRequest {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("ProofRequest({:p})", self))
    }
}

impl From<ProofRequest> for PyProofRequest {
    fn from(value: ProofRequest) -> Self {
        Self { inner: value }
    }
}

impl std::ops::Deref for PyProofRequest {
    type Target = ProofRequest;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[pyfunction]
/// Creates a new proof
pub fn create_proof(
    py: Python,
    proof_req: PyAcceptJsonArg<PyProofRequest>,
    credentials: HashMap<String, PyAcceptBufferArg<PyCredential>>, // mapping ident -> PyCredential
    requested_credentials: PyJsonArg<RequestedCredentials>,
    master_secret: PyAcceptBufferArg<PyMasterSecret>,
    schemas: HashMap<String, PyAcceptJsonArg<PySchema>>, // mapping ident -> PySchema
    cred_defs: HashMap<String, PyAcceptJsonArg<PyCredentialDefinition>>, // mapping ident -> PyCredentialDefinition
                                                                         // rev_states: &HashMap<String, HashMap<u64, RevocationState>>,
) -> PyResult<PyProof> {
    let proof_req = proof_req;
    let master_secret = master_secret.extract_json(py)?;
    let credentials =
        credentials
            .into_iter()
            .try_fold(HashMap::new(), |mut map, (k, cred)| -> PyResult<_> {
                map.insert(k, cred.extract_json(py)?);
                Ok(map)
            })?;
    let schema_refs = schemas
        .iter()
        .map(|(k, schema)| (SchemaId(k.clone()), &schema.inner))
        .collect();
    let cred_def_refs = cred_defs
        .iter()
        .map(|(k, cdef)| (CredentialDefinitionId(k.clone()), &cdef.inner))
        .collect();
    let proof = py
        .allow_threads(move || {
            Prover::create_proof(
                &proof_req,
                &credentials,
                &requested_credentials,
                &master_secret,
                &schema_refs,
                &cred_def_refs,
                &HashMap::new(),
            )
        })
        .map_py_err()?;
    Ok(PyProof::embed_json(py, &proof)?)
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_proof))?;
    m.add_class::<PyProof>()?;
    m.add_class::<PyProofRequest>()?;
    Ok(())
}
