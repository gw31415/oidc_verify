use crate::prelude::*;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use jwt_simple::prelude::*;
use reqwest::{get, IntoUrl};
use serde_json::Value;

pub use jwt_simple::prelude::JWTClaims;
pub use reqwest::Url;

/// A verifier for OpenID Connect.
#[derive(Clone)]
pub struct Verifier {
    issuer: Url,
    inner_jwks: Arc<RwLock<HashMap<String, RS256PublicKey>>>,
}

impl Verifier {
    /// Get the OpenID Configuration and check the required features.
    async fn openid_configuration(&self) -> Result<Value, ConnectionError> {
        let openid_configuration: Value = {
            let url = self
                .issuer
                .join(".well-known/openid-configuration")
                .or(Err(ConnectionError::ProgrammingError("invalid URL")))?;
            get(url)
                .await
                .or(Err(ConnectionError::UnreachedToIssuer))?
                .json::<Value>()
                .await
                .or(Err(ConnectionError::IssuerBroken(
                    "invalid JSON in openid-configuration",
                )))?
        };

        {
            // Assertion: The OpenID Provider supports the required features

            let response_type_supported = openid_configuration
                .get("response_types_supported")
                .ok_or(ConnectionError::IssuerBroken(
                    "no `response_types_supported` field",
                ))?
                .as_array()
                .ok_or(ConnectionError::IssuerBroken(
                    "the value of `response_types_supported` is not an array",
                ))?;

            if !response_type_supported.contains(&Value::String("id_token".to_string())) {
                return Err(ConnectionError::SupportsUnmatch);
            }

            let subject_types_supported = openid_configuration
                .get("subject_types_supported")
                .ok_or(ConnectionError::IssuerBroken(
                    "no `subject_types_supported` field",
                ))?
                .as_array()
                .ok_or(ConnectionError::IssuerBroken(
                    "the value of `subject_types_supported` is not an array",
                ))?;

            if !subject_types_supported.contains(&Value::String("public".to_string())) {
                return Err(ConnectionError::SupportsUnmatch);
            }

            let id_token_signing_alg_values_supported = openid_configuration
                .get("id_token_signing_alg_values_supported")
                .ok_or(ConnectionError::IssuerBroken(
                    "no `id_token_signing_alg_values_supported` field",
                ))?
                .as_array()
                .ok_or(ConnectionError::IssuerBroken(
                    "the value of `id_token_signing_alg_values_supported` is not an array",
                ))?;

            if !id_token_signing_alg_values_supported.contains(&Value::String("RS256".to_string()))
            {
                return Err(ConnectionError::SupportsUnmatch);
            }
        }

        Ok(openid_configuration)
    }

    /// Get the JWKS URI.
    async fn jwks_uri(&self) -> Result<Url, ConnectionError> {
        let jwks_uri: Url = self
            .openid_configuration()
            .await?
            .get("jwks_uri")
            .ok_or(ConnectionError::IssuerBroken("no `jwks_uri` field"))?
            .as_str()
            .ok_or(ConnectionError::IssuerBroken(
                "the value of `jwks_uri` is not a string",
            ))?
            .parse()
            .or(Err(ConnectionError::IssuerBroken(
                "the value of `jwks_uri` is not a valid URL",
            )))?;
        Ok(jwks_uri)
    }

    /// Verify a token and parse the claims.
    pub async fn verify<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        token: impl AsRef<str>,
    ) -> Result<JWTClaims<T>, VerifyError> {
        use VerifyError::InvalidToken;

        let metadata = Token::decode_metadata(token.as_ref())
            .or(Err(InvalidToken("could not decode the token metadata")))?;
        let kid = metadata
            .key_id()
            .ok_or(InvalidToken("no `kid` field in the token metadata"))?;

        let key = self.jwk(kid).await?;
        key.verify_token(token.as_ref(), None)
            .or(Err(InvalidToken("could not verify the token")))
    }

    /// Re-cache the JWKS.
    pub async fn recache_jwks(&self) -> Result<(), ConnectionError> {
        // Attempt to acquire (only once)

        let jwks = get(self.jwks_uri().await?)
            .await
            .or(Err(ConnectionError::UnreachedToIssuer))?
            .json::<Value>()
            .await
            .or(Err(ConnectionError::IssuerBroken("invalid JSON in JWKS")))?
            .get("keys")
            .ok_or(ConnectionError::IssuerBroken("no `keys` field in JWKS"))?
            .as_array()
            .ok_or(ConnectionError::IssuerBroken(
                "no `keys` field in JWKS is not an array",
            ))?
            .iter()
            .filter_map(|jwk| -> Option<(String, _)> {
                if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" {
                    return None;
                }
                if jwk["use"] != "sig" {
                    return None;
                }

                let e: &[u8] = &Base64UrlSafeNoPadding::decode_to_vec(
                    jwk["e"].as_str()?.trim_end_matches('='),
                    None,
                )
                .unwrap();
                let n: &[u8] = &Base64UrlSafeNoPadding::decode_to_vec(
                    jwk["n"].as_str()?.trim_end_matches('='),
                    None,
                )
                .unwrap();

                let key = RS256PublicKey::from_components(n, e).ok()?;

                let kid = jwk["kid"].as_str()?;

                Some((kid.to_string(), key))
            })
            .collect::<HashMap<_, _>>();
        *self.inner_jwks.write().unwrap() = jwks;
        Ok(())
    }

    /// Get a JWK by `kid`.
    async fn jwk(&self, kid: &str) -> Result<RS256PublicKey, VerifyError> {
        if let Some(key) = self.inner_jwks.read().unwrap().get(kid) {
            return Ok(key.clone());
        }

        // Could not find the key, so reacquired JWKS only once from the possibility of updating
        self.recache_jwks().await?;

        if let Some(key) = self.inner_jwks.read().unwrap().get(kid) {
            return Ok(key.clone());
        }

        Err(VerifyError::JwkNotFound)
    }

    /// Create a new `Verifier` instance.
    pub fn new(issuer: impl IntoUrl) -> Result<Verifier, ConnectionError> {
        Ok(Verifier {
            issuer: issuer
                .into_url()
                .or(Err(ConnectionError::ProgrammingError("invalid URL")))?,
            inner_jwks: Default::default(),
        })
    }
}
