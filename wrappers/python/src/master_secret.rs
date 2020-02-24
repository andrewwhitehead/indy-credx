use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use indy_credx::services as Services;
use indy_credx::services::prover::Prover;

use crate::buffer::PySafeBuffer;
use crate::error::PyIndyResult;

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

    // #[classmethod]
    // pub fn from_json(_cls: &PyType, json: &PyString) -> PyResult<Self> {
    //     let inner = serde_json::from_str::<CredentialDefinition>(&json.to_string()?)
    //         .map_py_err_msg("Error parsing credential definition JSON")?;
    //     Ok(Self { inner })
    // }

    // pub fn to_json(&self) -> PyResult<String> {
    //     Ok(serde_json::to_string(&self.inner).map_py_err()?)
    // }
}

impl PyMasterSecret {
    pub fn embed_json(py: Python, value: &Services::MasterSecret) -> PyResult<Self> {
        Ok(Self {
            inner: Py::new(py, PySafeBuffer::serialize(value)?)?,
        })
    }

    pub fn extract_json(&self, py: Python) -> PyResult<Services::MasterSecret> {
        self.inner.as_ref(py).deserialize()
    }
}

#[pyproto]
impl PyObjectProtocol for PyMasterSecret {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("MasterSecret({:p})", self))
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
