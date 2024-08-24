/// An error that occurred while verifying a token.
#[derive(Debug, thiserror::Error, Clone)]
pub enum VerifyError {
    /// The token is invalid.
    #[error("invalid token: {0}")]
    InvalidToken(&'static str),

    /// The jwk of the token is not found.
    #[error("the jwk not found")]
    JwkNotFound,

    /// Could not check the token because the verifier is not connected to the issuer.
    #[error(transparent)]
    NotConnected(#[from] ConnectionError),
}

/// An error that occurred while connecting to the issuer.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ConnectionError {
    /// The issuer is unreachable.
    #[error("could not reach the issuer or get the openid-configuration")]
    UnreachedToIssuer,

    /// The issuer is unsupported.
    #[error("the issuer does not support the required features")]
    SupportsUnmatch,

    /// The issuer is broken.
    #[error("the issuer is broken: {0}")]
    IssuerBroken(&'static str),

    /// Invalid usage.
    #[error("invalid usage: {0}")]
    ProgrammingError(&'static str),
}
