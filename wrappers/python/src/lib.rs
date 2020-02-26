#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod buffer;
mod cred;
mod cred_def;
mod cred_offer;
mod cred_request;
mod error;
mod helpers;
mod master_secret;
mod proof;
mod schema;

#[pyfunction]
/// Creates a new test buffer
fn create_test_buffer() -> PyResult<buffer::PySafeBuffer> {
    let buffer = buffer::PySafeBuffer::new(vec![b'a', b'b', b'c']);
    Ok(buffer)
}

/// Initializes the default logger
fn set_default_logger() {
    env_logger::init();
    debug!("Initialized default logger");
}

/// This module is a python module implemented in Rust.
#[pymodule]
fn indy_credx(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_test_buffer))?;

    cred::register(py, m)?;
    cred_def::register(py, m)?;
    cred_offer::register(py, m)?;
    cred_request::register(py, m)?;
    master_secret::register(py, m)?;
    proof::register(py, m)?;
    schema::register(py, m)?;

    m.add_class::<buffer::PySafeBuffer>()?;
    set_default_logger();

    Ok(())
}
