# oidc_verifier

This is a simple library to verify the JWT token of RS256 received from the OIDC provider.
This works without It works without `authorization_endpoint` field, such as Firebase Auth.

## Usage

```rust
use oidc_verify::prelude::*;
use serde_json::Value;

#[tokio::main]
async fn main() {
    let verifier = Verifier::new("https://securetoken.google.com/hogehoge-fugafuga/").unwrap();

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
