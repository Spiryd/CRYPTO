//! API error types

#[derive(Debug)]
pub enum ApiError {
    Network(reqwest::Error),
    Json(serde_json::Error),
    Validation(String),
    SignatureVerification(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        ApiError::Network(err)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::Json(err)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Network(e) => write!(f, "Network error: {}", e),
            ApiError::Json(e) => write!(f, "JSON error: {}", e),
            ApiError::Validation(s) => write!(f, "Validation error: {}", s),
            ApiError::SignatureVerification(s) => write!(f, "Signature verification failed: {}", s),
        }
    }
}

impl std::error::Error for ApiError {}
