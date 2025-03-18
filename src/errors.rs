use reqwest::header::InvalidHeaderName;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NcError {
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Header parse error: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("Header name parsing error: {0}")]
    InvalidHeaderName(#[from] InvalidHeaderName),

    #[error("Header value contained invalid UTF-8 characters: {0}")]
    ToStrError(#[from] reqwest::header::ToStrError),

    #[error("UTF-8 parse error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("Authentication failed with status code {0}")]
    AuthenticationFailed(u16),

    #[error("Unexpected response (status: {status}, body: {body})")]
    UnexpectedResponse { status: u16, body: String },

    #[error("Missing required field: {0}")]
    MissingField(String),
}
