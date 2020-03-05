#[derive(Clone, Debug)]
pub struct ValidationError(pub Option<String>);

impl From<String> for ValidationError {
    fn from(msg: String) -> Self {
        Self(Some(msg))
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .as_ref()
                .map(String::as_str)
                .unwrap_or("Validation error")
        )
    }
}

#[macro_export]
macro_rules! invalid {
    ($($arg:tt)+) => {
        ValidationError::from(format!($($arg)+))
    };
}

pub trait Validatable {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}
