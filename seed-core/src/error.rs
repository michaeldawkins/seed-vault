use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// The input could not be read as the expected format.
    Malformed(String),
    /// A signature did not verify.
    BadSignature(String),
    /// A value broke a rule (for example a mandate that grants a forbidden action).
    Invalid(String),
    /// Something was not found (an agent, a mandate).
    NotFound(String),
    /// Reading or writing a file failed.
    Io(String),
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedError::Malformed(m) => write!(f, "malformed: {m}"),
            SeedError::BadSignature(m) => write!(f, "bad signature: {m}"),
            SeedError::Invalid(m) => write!(f, "not allowed: {m}"),
            SeedError::NotFound(m) => write!(f, "not found: {m}"),
            SeedError::Io(m) => write!(f, "file problem: {m}"),
        }
    }
}

impl std::error::Error for SeedError {}

impl From<serde_json::Error> for SeedError {
    fn from(e: serde_json::Error) -> Self {
        SeedError::Malformed(e.to_string())
    }
}

impl From<std::io::Error> for SeedError {
    fn from(e: std::io::Error) -> Self {
        SeedError::Io(e.to_string())
    }
}
