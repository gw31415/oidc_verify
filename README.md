# oidc_verify

[![Crates.io](https://img.shields.io/crates/v/oidc_verify?style=flat-square)](https://crates.io/crates/oidc_verify)
[![Crates.io](https://img.shields.io/crates/d/oidc_verify?style=flat-square)](https://crates.io/crates/oidc_verify)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)

This is a simple library to verify the JWT token of RS256 received from the OIDC provider.
This works without It works without `authorization_endpoint` field, such as Firebase Auth.

## Dependencies

This library depends on `tokio` as an async runtime, so your project should select `tokio`
as an async runtime too.

## Usage

```rust
use oidc_verify::prelude::*;
use serde_json::Value;

#[tokio::main]
async fn main() {
    let verifier = Verifier::new("https://securetoken.google.com/hogehoge-fugafuga/");

    let token = "Bearer 3x4mple.t0k3n".strip_prefix("Bearer ").unwrap();

    match verifier.verify::<Value>(token).await {
        Ok(claims) => {
            println!("Claims: {}", serde_json::to_string_pretty(&claims).unwrap());
        },
        Err(err) => {
            println!("Error: {:?}", err);
        },
    }
}
```

## License

Apache 2.0
