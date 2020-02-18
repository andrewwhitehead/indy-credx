#[macro_export]
macro_rules! assert_kind {
    ($kind:expr, $var:expr) => {
        match $var {
            Err(e) => assert_eq!($kind, *e.kind()),
            _ => assert!(false, "Result expected to be error"),
        }
    };
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! secret {
    ($val:expr) => {{
        $val
    }};
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! secret {
    ($val:expr) => {{
        "_"
    }};
}
