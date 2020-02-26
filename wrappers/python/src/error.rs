use pyo3::create_exception;
use pyo3::exceptions::Exception;
use pyo3::prelude::*;

use indy_credx::common::error::IndyError as LibError;

create_exception!(indy_credx, IndyError, Exception);

pub trait PyIndyResult<T> {
    fn map_py_err(self) -> PyResult<T>;
    fn map_py_err_msg<F, M>(self, msgfn: F) -> PyResult<T>
    where
        F: FnOnce() -> M,
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static;
}

impl<T, E> PyIndyResult<T> for Result<T, E>
where
    E: Into<LibError>,
{
    fn map_py_err(self) -> PyResult<T> {
        match self {
            Ok(r) => Ok(r),
            Err(err) => Err(PyErr::new::<IndyError, _>(err.into().to_string())),
        }
    }

    fn map_py_err_msg<F, M>(self, msgfn: F) -> PyResult<T>
    where
        F: FnOnce() -> M,
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        match self {
            Ok(r) => Ok(r),
            Err(err) => Err(PyErr::new::<IndyError, _>(
                err.into().extend(msgfn()).to_string(),
            )),
        }
    }
}
