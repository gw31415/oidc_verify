use crate::prelude::*;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use jwt_simple::prelude::*;
use serde_json::Value;

pub use jwt_simple::prelude::JWTClaims;
pub use url::Url;

/// Fetch JSON and parse as `T` from the URL. Fetching process is processed in a new blocking-thread.
async fn fetch_json<T>(url: Url) -> Result<T, FetchError>
where
    T: serde::de::DeserializeOwned,
{
    {
        use tokio::task::spawn_blocking;
        use ureq::get;
        spawn_blocking(move || {
            get(url.as_str())
                .call()
                .or(Err(FetchError::NetworkError(url)))
        })
    }
    .await
    .expect("the spawned blocking task are not supposed to panic or cancel")?
    .into_json::<T>()
    .or(Err(FetchError::ParseError))
}

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
            let url = self.issuer.join(".well-known/openid-configuration").expect(
                "the issuer and `.well-known/openid-configuration` URL must be a valid URL/path",
            );
            fetch_json::<Value>(url).await?
        };

        {
            // Assertion: The OpenID Provider supports the required features

            let response_type_supported = openid_configuration
                .get("response_types_supported")
                .ok_or(ConnectionError::BrokenConfiguration)?
                .as_array()
                .ok_or(ConnectionError::BrokenConfiguration)?;

            if !response_type_supported.contains(&Value::String("id_token".to_string())) {
                return Err(ConnectionError::UnmatchConfiguration);
            }

            let subject_types_supported = openid_configuration
                .get("subject_types_supported")
                .ok_or(ConnectionError::BrokenConfiguration)?
                .as_array()
                .ok_or(ConnectionError::BrokenConfiguration)?;

            if !subject_types_supported.contains(&Value::String("public".to_string())) {
                return Err(ConnectionError::UnmatchConfiguration);
            }

            let id_token_signing_alg_values_supported = openid_configuration
                .get("id_token_signing_alg_values_supported")
                .ok_or(ConnectionError::BrokenConfiguration)?
                .as_array()
                .ok_or(ConnectionError::BrokenConfiguration)?;

            if !id_token_signing_alg_values_supported.contains(&Value::String("RS256".to_string()))
            {
                return Err(ConnectionError::UnmatchConfiguration);
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
            .ok_or(ConnectionError::BrokenConfiguration)?
            .as_str()
            .ok_or(ConnectionError::BrokenConfiguration)?
            .parse()
            .or(Err(ConnectionError::BrokenConfiguration))?;
        Ok(jwks_uri)
    }

    /// Verify a token and parse the claims.
    pub async fn verify<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        token: impl AsRef<str>,
    ) -> Result<JWTClaims<T>, VerifyError> {
        let metadata = Token::decode_metadata(token.as_ref()).or(Err(ValidationError::Broken))?;
        let kid = metadata
            .key_id()
            .ok_or(ConnectionError::BrokenConfiguration)?;

        let key = self.jwk(kid).await?;
        key.verify_token(token.as_ref(), None)
            .or(Err(ValidationError::Invalid.into()))
    }

    /// Re-cache the JWKS.
    pub async fn recache_jwks(&self) -> Result<(), ConnectionError> {
        // Attempt to acquire (only once)

        let jwks = fetch_json::<Value>(self.jwks_uri().await?)
            .await?
            .get("keys")
            .ok_or(ConnectionError::BrokenConfiguration)?
            .as_array()
            .ok_or(ConnectionError::BrokenConfiguration)?
            .iter()
            .filter_map(|jwk| -> Option<(String, _)> {
                // Parse the JWKs to pairs of `kid` and `RS256PublicKey`.
                // If unsupported JWKs are found or invalid JWKs are found, they are ignored and
                // filtered out

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
                .ok()?;
                let n: &[u8] = &Base64UrlSafeNoPadding::decode_to_vec(
                    jwk["n"].as_str()?.trim_end_matches('='),
                    None,
                )
                .ok()?;

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

        // Could not find the key, so reacquired JWKS only once from the possibility of updating.
        self.recache_jwks().await?;

        if let Some(key) = self.inner_jwks.read().unwrap().get(kid) {
            return Ok(key.clone());
        }

        Err(ValidationError::PubkeyNotFound.into())
    }

    /// Create a new `Verifier` instance.
    pub fn new(issuer: Url) -> Verifier {
        Verifier {
            issuer,
            inner_jwks: Default::default(),
        }
    }
}
