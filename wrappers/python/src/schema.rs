use std::collections::HashSet;

use pyo3::class::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::{PySequence, PyString};
use pyo3::wrap_pyfunction;
use pyo3::ObjectProtocol;

use indy_credx::common::did::DidValue;
use indy_credx::domain::schema::Schema;
use indy_credx::services as Services;
use indy_credx::services::issuer::Issuer;

#[pyclass(name=Schema)]
pub struct PySchema {
    pub inner: Schema,
}

#[pymethods]
impl PySchema {
    #[getter]
    pub fn schema_id(&self) -> PyResult<String> {
        match &self.inner {
            Schema::SchemaV1(s) => Ok(s.id.to_string()),
        }
    }

    #[getter]
    pub fn get_seq_no(&self) -> PyResult<Option<u32>> {
        match &self.inner {
            Schema::SchemaV1(s) => Ok(s.seq_no),
        }
    }

    #[setter]
    pub fn set_seq_no(&mut self, seq_no: Option<u32>) -> PyResult<()> {
        match &mut self.inner {
            Schema::SchemaV1(s) => {
                s.seq_no = seq_no;
                Ok(())
            }
        }
    }

    #[getter]
    pub fn name(&self) -> PyResult<String> {
        match &self.inner {
            Schema::SchemaV1(s) => Ok(s.name.clone()),
        }
    }

    #[getter]
    pub fn version(&self) -> PyResult<String> {
        match &self.inner {
            Schema::SchemaV1(s) => Ok(s.version.clone()),
        }
    }

    #[getter]
    pub fn attr_names(&self) -> PyResult<Vec<String>> {
        match &self.inner {
            Schema::SchemaV1(s) => Ok(s.attr_names.0.iter().cloned().collect()),
        }
    }

    pub fn to_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string(&self.inner).unwrap())
    }
}

#[pyproto]
impl PyObjectProtocol for PySchema {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Schema({})", self.schema_id()?))
    }
}

#[pyfunction]
/// Creates a new schema
fn create_schema(
    py: Python,
    origin_did: &PyString,
    schema_name: &PyString,
    schema_version: &PyString,
    attr_names: PyObject,
) -> PyResult<PySchema> {
    let origin_did = origin_did.to_string()?;
    let schema_name = schema_name.to_string()?;
    let schema_version = schema_version.to_string()?;
    let mut attrs = HashSet::new();
    let attr_names = attr_names.cast_as::<PySequence>(py)?;
    for attr in attr_names.iter()? {
        attrs.insert(ObjectProtocol::extract::<String>(attr?)?);
    }
    let attr_names = Services::AttributeNames::from(attrs);
    let schema = Issuer::new_schema(
        &DidValue(origin_did.into_owned()),
        &*schema_name,
        &*schema_version,
        attr_names,
    )
    .unwrap();
    Ok(PySchema { inner: schema })
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_schema))?;
    m.add_class::<PySchema>()?;
    Ok(())
}
