use url::Url;

/// An error that occurred while verifying a token.
#[derive(Debug, thiserror::Error, Clone)]
pub enum VerifyError {
    /// The token is invalid. Equivalent to an authentication error (401 error).
    #[error(transparent)]
    ValidationFailed(#[from] ValidationError),

    /// Could not check the token because the verifier is not connected to the issuer.
    /// Equivalent to a internal server error (500 error).
    #[error(transparent)]
    NotConnected(#[from] ConnectionError),
}

/// An error that occurred while validating a token.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ValidationError {
    /// The token is broken.
    #[error("the token is broken")]
    Broken,

    /// The pubkey is not found.
    #[error("the pubkey not found")]
    PubkeyNotFound,

    /// The token is invalid.
    #[error("the token is invalid")]
    Invalid,
}

/// An error that occurred while connecting to the issuer.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ConnectionError {
    /// An error occurred while fetching data.
    #[error(transparent)]
    FetchError(#[from] FetchError),

    /// The issuer configuration is unsupported.
    #[error("the issuer does not support the required features")]
    UnmatchConfiguration,

    /// The issuer configuration is broken.
    #[error("the openid-configuration is broken.")]
    BrokenConfiguration,
}

/// An error that occurred while fetching data.
#[derive(Debug, thiserror::Error, Clone)]
pub enum FetchError {
    /// Could not fetch the URL.
    #[error("could not fetch the URL: {0}")]
    NetworkError(Url),

    /// Could not parse the data as JSON or specific-structured JSON.
    #[error("could not parse the data")]
    ParseError,
}
