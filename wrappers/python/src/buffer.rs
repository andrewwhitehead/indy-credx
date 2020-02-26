use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::ptr;

use pyo3::class::{PyBufferProtocol, PyObjectProtocol};
use pyo3::exceptions::BufferError;
use pyo3::ffi::{PyBUF_FORMAT, PyBUF_ND, PyBUF_STRIDES, PyBUF_WRITABLE, Py_INCREF, Py_buffer};
use pyo3::prelude::*;
use pyo3::{AsPyPointer, PyClassShell};

use zeroize::Zeroize;

use indy_credx::common::error::IndyResult;

#[pyclass(name=SafeBuffer)]
pub struct PySafeBuffer {
    inner: Vec<u8>,
}

#[pyproto]
impl PyBufferProtocol for PySafeBuffer {
    fn bf_getbuffer(
        slf: &mut PyClassShell<Self>,
        view: *mut Py_buffer,
        flags: c_int,
    ) -> PyResult<()> {
        if view.is_null() {
            return Err(BufferError::py_err("View is null"));
        }
        if (flags & PyBUF_WRITABLE) == PyBUF_WRITABLE {
            return Err(BufferError::py_err("Object is not writable"));
        }

        let bytes = &slf.inner;
        unsafe {
            debug!("create memory view {:p}", &bytes);
            (*view).obj = slf.as_ptr();
            Py_INCREF((*view).obj);

            (*view).buf = bytes.as_ptr() as *mut c_void;
            (*view).len = bytes.len() as isize;
            (*view).readonly = 1;
            (*view).itemsize = 1;

            (*view).format = ptr::null_mut();
            if (flags & PyBUF_FORMAT) == PyBUF_FORMAT {
                let msg = CStr::from_bytes_with_nul(b"B\0").unwrap();
                (*view).format = msg.as_ptr() as *mut _;
            }

            (*view).ndim = 1;
            (*view).shape = ptr::null_mut();
            if (flags & PyBUF_ND) == PyBUF_ND {
                (*view).shape = (&((*view).len)) as *const _ as *mut _;
            }

            (*view).strides = ptr::null_mut();
            if (flags & PyBUF_STRIDES) == PyBUF_STRIDES {
                (*view).strides = &((*view).itemsize) as *const _ as *mut _;
            }

            (*view).suboffsets = ptr::null_mut();
            (*view).internal = ptr::null_mut();
        }
        Ok(())
    }

    fn bf_releasebuffer(slf: &mut PyClassShell<Self>, view: *mut Py_buffer) -> PyResult<()> {
        if view.is_null() {
            return Err(BufferError::py_err("View is null"));
        }
        debug!("release memory view {:p}", &slf.inner);
        // Python will have already decreased the reference count of view.obj
        Ok(())
    }
}

#[pyproto]
impl PyObjectProtocol for PySafeBuffer {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("SafeBuffer({:p})", self))
    }
}

impl PySafeBuffer {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { inner: buf }
    }

    pub fn serialize<T>(value: &T) -> IndyResult<Self>
    where
        T: serde::Serialize,
    {
        let json = serde_json::to_vec(value)?;
        Ok(Self::new(json))
    }

    pub fn deserialize<T>(&self) -> IndyResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let result = serde_json::from_slice::<T>(self.inner.as_slice())?;
        Ok(result)
    }

    pub fn from_json_insecure<T>(json: &str) -> IndyResult<Self>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let value = serde_json::from_str::<T>(json)?;
        Self::serialize(&value)
    }

    pub fn to_json_insecure<T>(&self) -> IndyResult<String> {
        Ok(String::from_utf8_lossy(&self.inner).to_string())
    }
}

impl Drop for PySafeBuffer {
    fn drop(&mut self) {
        debug!("zero buffer {:p}", &self.inner);
        self.inner.zeroize()
    }
}
