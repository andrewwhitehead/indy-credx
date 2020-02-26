use std::marker::PhantomData;

use pyo3::buffer::PyBuffer;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyString};
use pyo3::PyTypeInfo;

use crate::buffer::PySafeBuffer;
use crate::error::PyIndyResult;

pub enum PyArg<'a, T, M = T> {
    Owned(T, PhantomData<M>),
    Ref(&'a T, PhantomData<M>),
}

impl<'a, T, M> std::ops::Deref for PyArg<'a, T, M> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Self::Owned(x, _) => x,
            Self::Ref(x, _) => x,
        }
    }
}

#[allow(dead_code)]
pub type PyJsonArg<'a, T> = PyArg<'a, T, ArgAsJson<T>>;
pub type PyAcceptJsonArg<'a, T> = PyArg<'a, T, ArgAcceptRef<ArgAsJson<T>>>;
pub type PyAcceptBufferArg<'a, T> = PyArg<'a, T, ArgAcceptRef<ArgAsSafeBuffer<T>>>;

fn extract_json<T>(obj: &PyAny) -> PyResult<T>
where
    T: serde::de::DeserializeOwned,
{
    if PyString::is_instance(obj) {
        serde_json::from_str::<T>(&<PyString as PyTryFrom>::try_from(obj)?.to_string()?)
            .map_py_err_msg(|| format!("Error deserializing JSON"))
    } else {
        let py = unsafe { Python::assume_gil_acquired() };
        let buffer = PyBuffer::get(py, obj)?;
        let data =
            unsafe { std::slice::from_raw_parts(buffer.buf_ptr() as *mut u8, buffer.len_bytes()) };
        serde_json::from_slice::<T>(data).map_py_err_msg(|| format!("Error deserializing JSON"))
    }
}

pub trait PyExtractArg<'a> {
    type Result;
    fn extract_arg<M>(py: Python, arg: &'a PyAny) -> PyResult<PyArg<'a, Self::Result, M>>;
}

impl<'a, T: 'a> PyExtractArg<'a> for T
where
    &'a T: FromPyObject<'a>,
{
    type Result = T;
    fn extract_arg<M>(_py: Python, arg: &'a PyAny) -> PyResult<PyArg<'a, Self::Result, M>> {
        Ok(PyArg::Ref(
            <&T as FromPyObject<'a>>::extract(arg)?,
            PhantomData,
        ))
    }
}

impl<'a, T: 'a, M> FromPyObject<'a> for PyArg<'a, T, M>
where
    M: PyExtractArg<'a, Result = T>,
{
    fn extract(arg: &'a PyAny) -> PyResult<Self> {
        let py = unsafe { Python::assume_gil_acquired() };
        Ok(M::extract_arg(py, arg)?)
    }
}

pub struct ArgAsJson<T> {
    _pd: PhantomData<T>,
}

impl<'a, T> PyExtractArg<'a> for ArgAsJson<T>
where
    T: serde::de::DeserializeOwned,
{
    type Result = T;
    fn extract_arg<M>(_py: Python, arg: &'a PyAny) -> PyResult<PyArg<'a, T, M>> {
        Ok(PyArg::Owned(extract_json(arg)?, PhantomData))
    }
}

pub struct ArgAcceptRef<T> {
    _pd: PhantomData<T>,
}

impl<'a, T> PyExtractArg<'a> for ArgAcceptRef<T>
where
    T: PyExtractArg<'a> + 'a,
    <T as PyExtractArg<'a>>::Result: 'a,
    T::Result: PyTypeInfo,
    &'a T::Result: FromPyObject<'a>,
{
    type Result = T::Result;
    fn extract_arg<M>(py: Python, arg: &'a PyAny) -> PyResult<PyArg<'a, Self::Result, M>> {
        if Self::Result::is_instance(arg) {
            Ok(PyArg::Ref(
                <Self::Result as PyTryFrom>::try_from(arg)?,
                PhantomData,
            ))
        } else {
            T::extract_arg(py, arg)
        }
    }
}

pub struct ArgAsSafeBuffer<T> {
    _pd: PhantomData<T>,
}

impl<'a, T> PyExtractArg<'a> for ArgAsSafeBuffer<T>
where
    T: From<Py<PySafeBuffer>>,
{
    type Result = T;
    fn extract_arg<M>(py: Python, arg: &'a PyAny) -> PyResult<PyArg<'a, Self::Result, M>> {
        let result = if PyString::is_instance(arg) {
            <PyString as PyTryFrom>::try_from(arg)?
                .to_string()?
                .as_bytes()
                .to_vec()
        } else {
            PyBuffer::get(py, arg)?.to_vec(py)?
        };
        let buf = Py::new(py, PySafeBuffer::new(result))?;
        Ok(PyArg::Owned(T::from(buf), PhantomData))
    }
}

pub trait PyJsonSafeBuffer: From<Py<PySafeBuffer>> + PyTypeInfo {
    type Inner: serde::de::DeserializeOwned + serde::Serialize;

    fn buffer(&self, py: Python) -> &PySafeBuffer;

    fn embed_json(py: Python, value: &Self::Inner) -> PyResult<Self> {
        Ok(Self::from(Py::new(
            py,
            PySafeBuffer::serialize(value)
                .map_py_err_msg(|| format!("Error parsing {} as JSON", Self::NAME))?,
        )?))
    }

    fn extract_json(&self, py: Python) -> PyResult<Self::Inner> {
        self.buffer(py)
            .deserialize()
            .map_py_err_msg(|| format!("Error parsing {} as JSON", Self::NAME))
    }

    fn to_json_insecure(&self, py: Python) -> PyResult<String> {
        Ok(self
            .buffer(py)
            .to_json_insecure::<Self::Inner>()
            .map_py_err_msg(|| format!("Error serializing {} as JSON", Self::NAME))?)
    }

    fn from_json_insecure(py: Python, json: &PyString) -> PyResult<Self> {
        let inner = Py::new(
            py,
            PySafeBuffer::from_json_insecure::<Self::Inner>(&json.to_string()?)
                .map_py_err_msg(|| format!("Error parsing {} as JSON", Self::NAME))?,
        )?;
        Ok(Self::from(inner))
    }
}
