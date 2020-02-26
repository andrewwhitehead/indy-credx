use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};
use pyo3::wrap_pyfunction;

use indy_credx::services::prover::Prover;
use indy_credx::services::MasterSecret;

use crate::buffer::PySafeBuffer;
use crate::error::PyIndyResult;
use crate::helpers::PyJsonSafeBuffer;

#[pyclass(name=MasterSecret)]
pub struct PyMasterSecret {
    pub inner: Py<PySafeBuffer>,
}

#[pymethods]
impl PyMasterSecret {
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
impl PyObjectProtocol for PyMasterSecret {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("MasterSecret({:p})", self))
    }
}

impl From<Py<PySafeBuffer>> for PyMasterSecret {
    fn from(inner: Py<PySafeBuffer>) -> Self {
        Self { inner }
    }
}

impl PyJsonSafeBuffer for PyMasterSecret {
    type Inner = MasterSecret;
    fn buffer(&self, py: Python) -> &PySafeBuffer {
        self.inner.as_ref(py)
    }
}

#[pyfunction]
/// Creates a new master secret
pub fn create_master_secret(py: Python) -> PyResult<PyMasterSecret> {
    let secret = Prover::new_master_secret().map_py_err()?;
    Ok(PyMasterSecret::embed_json(py, &secret)?)
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_master_secret))?;
    m.add_class::<PyMasterSecret>()?;
    Ok(())
}
