# Protobuf Web Token (PWT)

**A Rust library for creating, signing, and verifying compact binary web tokens using Protocol Buffers and Ed25519 signatures.**

This crate is a fork of [`protobuf-web-token`](https://crates.io/crates/protobuf-web-token) that replaces the `prost` dependency with the official `protobuf` crate.

## Why PWT over JWT?

Traditional JSON Web Tokens (JWTs) use JSON encoding, which is inefficient for data transfer compared to compact binary encodings like Protocol Buffers. PWTs provide:

- **🚀 2.5x faster** encoding/decoding performance
- **📦 25-60% smaller** token size
- **🔒 Type safety** at compile time
- **🎯 Ed25519** signatures for modern cryptography

### Performance Comparison

| Metric | Simple Data | Complex Data |
|--------|-------------|--------------|
| **Speed** | PWT 2.5x faster | PWT 2.6x faster |
| **Size** | PWT 25% smaller | PWT 60% smaller |

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
pwt = "0.8"
protobuf = "3.7" # 4.0 has removed serde support as well as other features
```

### 1. Define Your Claims Schema

Create a `.proto` file defining your token claims:

```protobuf
syntax = "proto3";

package test;

message UserClaims {
  int64 user_id = 1;
  string username = 2;
  string email = 3;
  repeated Role roles = 4;
}
```

### 2. Generate Rust Code

Add to your `build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    protobuf_codegen::Codegen::new()
       .out_dir("tests/generated")
       .include(".")
       .input("tests/fixtures/test.proto")
       .run()?;
    Ok(())
}
```

### 3. Sign and Verify Tokens

```rust
use pwt::{Signer, ed25519::SigningKey};
use std::time::Duration;

// Include your generated protobuf code
mod generated {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/generated/mod.rs"));
}
use generated::test::UserClaims;

// Create a signer with your Ed25519 private key
let signing_key = SigningKey::from_bytes(&[1u8; 32]); // Use your actual key
let signer = Signer::new(signing_key);

// Create your claims using the generated protobuf struct
let claims = UserClaims {
    user_id: 12345,
    username: "alice".to_string(),
    email: "alice@example.com".to_string(),
    ..Default::default()
};

// Sign the token (valid for 1 hour)
let token = signer.sign(&claims, Duration::from_secs(3600));

// Verify and decode the token
let verifier = signer.as_verifier();
let decoded = verifier.verify::<UserClaims>(&token)?;

println!("User ID: {}", decoded.claims.user_id);
println!("Username: {}", decoded.claims.username);
println!("Valid until: {:?}", decoded.valid_until);
```

## Token Formats

PWT supports two token formats:

### String Format (URL-safe)
```
{base64_data}.{base64_signature}
```
- Use [`Signer::sign`] and [`Verifier::verify`]
- Best for HTTP headers, URLs, and text protocols

### Binary Format (compact)
```rust
use pwt::{Signer, ed25519::SigningKey};
use std::time::Duration;

#
// Create a signer
let signing_key = SigningKey::from_bytes(&[1u8; 32]);
let signer = Signer::new(signing_key);

// Create claims using your generated protobuf struct
let claims = Simple {
    some_claim: "binary example".to_string(),
    ..Default::default()
};

// Sign as bytes (most compact format)
let token_bytes = signer.sign_to_bytes(&claims, Duration::from_secs(3600));
let decoded = signer.as_verifier().verify_bytes::<Simple>(&token_bytes)?;
```
- Use [`Signer::sign_to_bytes`] and [`Verifier::verify_bytes`]
- Most compact format for binary protocols

## Differences from Upstream

This fork makes several improvements over the original [`protobuf-web-token`](https://crates.io/crates/protobuf-web-token):

- **🔄 Migrated from `prost` to official `protobuf` crate** for better ecosystem compatibility
- **🛡️ Removed unsafe operations** - Added `try_*` methods for all potentially failing operations
- **🧹 Rust-only focus** - Removed Elm and TypeScript bindings for cleaner codebase
- **🧹 API improvements**
  - Exposed SignedToken and Token structs as public
  - Added `fn decode_claims(bytes: &[u8]) -> Result<CLAIMS, Error>` to decode only the `CLAIMS` without verification
  - Added `fn decode(bytes: &[u8]) -> Result<TokenData<CLAIMS>, Error>` to decode the `CLAIMS` and expiry without verification
  - Renamed old `fn decode(token: &str) -> Result<TokenData<CLAIMS>, Error>` to `decode_str`
- **📊 Better error handling** - More descriptive error types with context
- **🧪 Comprehensive testing** - Added extensive test coverage including fuzzing
- **📚 Improved documentation** - Better examples and API documentation

## Security Notes

- **Ed25519 signatures only**: No algorithm negotiation reduces attack surface
- **Automatic expiration**: All tokens include `valid_until` timestamp
- **Tamper detection**: Any modification invalidates the signature
- **Type safety**: Compile-time verification of token structure

## When to Use PWT

PWT is ideal when you:
- Control both the token issuer and consumer
- Want better performance than JWT
- Prefer compile-time type safety
- Need compact binary tokens
- Use Protocol Buffers elsewhere in your stack

For maximum interoperability with existing systems, stick with JWT.

## Motivation

The benefit of PWT is obvious if you are using protobuf anyway and want to avoid JSON just for JWT.

I forked the original crate because [`prost`](https://crates.io/crates/prost) is incompatible with [`protobuf`](https://crates.io/crates/protobuf),
poorly documented, depends on macros **in the generated code** (making it hard to debug), and my project was already using [`protobuf`](https://crates.io/crates/protobuf).

## Credits

Credit to original author [Andreas Molitor (anmolitor)](https://crates.io/users/anmolitor) for [`protobuf-web-token`](https://crates.io/crates/protobuf-web-token).

License: 	BSD-3-Clause
