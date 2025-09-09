use std::{
    fmt::Display,
    time::{Duration, SystemTime},
};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use protobuf::{Message, MessageField};

use base64::{Engine as _, engine::general_purpose};

#[cfg(test)]
mod jwt;

mod generated;
use generated::pwt as proto;

pub use ed25519_dalek as ed25519;

#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Verifier {
    key: VerifyingKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenData<CLAIMS> {
    pub valid_until: SystemTime,
    pub claims: CLAIMS,
}

struct Base64Claims<'a>(&'a str);

struct Base64Signature<'a>(&'a str);

struct BytesClaims(Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidFormat,
    InvalidBase64,
    InvalidSignature,
    SignatureMismatch,
    ProtobufDecodeError(String),
    MissingValidUntil,
    TokenExpired,
}

impl Signer {
    /// Creates a new `Signer` from an ed25519 `SigningKey` (private key)
    pub fn new(key: SigningKey) -> Self {
        Signer { key }
    }

    /// Creates a `Verifier` which can decode and verify PWT but can not sign them
    pub fn as_verifier(&self) -> Verifier {
        Verifier {
            key: self.key.verifying_key(),
        }
    }

    /// Encodes a `Message` into a PWT. Uses the URL-safe string representation:
    /// {data_in_base64}.{signature_of_encoded_bytes_in_base64}.
    ///
    /// # Panics
    ///
    /// This method panics if the protobuf encoding fails, which should not happen
    /// with valid input data structures. For a non-panicking version, use `try_sign`.
    pub fn sign<T: Message>(&self, data: &T, valid_for: Duration) -> String {
        self.try_sign(data, valid_for)
            .expect("Failed to create token - this should not happen with valid input")
    }

    /// Encodes a `Message` into a PWT. Uses the URL-safe string representation:
    /// {data_in_base64}.{signature_of_encoded_bytes_in_base64}.
    ///
    /// Returns an error if protobuf encoding fails.
    pub fn try_sign<T: Message>(&self, data: &T, valid_for: Duration) -> Result<String, Error> {
        let proto_token = self.create_proto_token(data, valid_for)?;
        let (base64, signature) = self.sign_proto_token(&proto_token)?;
        Ok(format!("{base64}.{signature}"))
    }

    /// Encodes a `Message` into a PWT. Uses the compact byte representation via a protobuf message with
    /// 2 fields (data and signature).
    ///
    /// # Panics
    ///
    /// This method panics if the protobuf encoding fails, which should not happen
    /// with valid input data structures. For a non-panicking version, use `try_sign_to_bytes`.
    pub fn sign_to_bytes<T: Message>(&self, data: &T, valid_for: Duration) -> Vec<u8> {
        self.try_sign_to_bytes(data, valid_for)
            .expect("Failed to encode protobuf - this should not happen with valid input")
    }

    /// Encodes a `Message` into a PWT. Uses the compact byte representation via a protobuf message with
    /// 2 fields (data and signature). Returns an error if encoding fails.
    pub fn try_sign_to_bytes<T: Message>(
        &self,
        data: &T,
        valid_for: Duration,
    ) -> Result<Vec<u8>, Error> {
        let proto_token = self.create_proto_token(data, valid_for)?;
        let bytes = proto_token
            .write_to_bytes()
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        let signature = self.key.sign(&bytes);
        proto::SignedToken {
            data: bytes,
            signature: signature.to_bytes().to_vec(),
            ..Default::default()
        }
        .write_to_bytes()
        .map_err(|e| Error::ProtobufDecodeError(e.to_string()))
    }

    fn create_proto_token<T: Message>(
        &self,
        data: &T,
        valid_for: Duration,
    ) -> Result<proto::Token, Error> {
        let bytes = data
            .write_to_bytes()
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        Ok(proto::Token {
            valid_until: MessageField::some((SystemTime::now() + valid_for).into()),
            claims: bytes,
            ..Default::default()
        })
    }

    fn sign_proto_token(&self, proto_token: &proto::Token) -> Result<(String, String), Error> {
        let bytes = proto_token
            .write_to_bytes()
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        let signature = self.key.sign(&bytes);
        let base64 = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let signature = general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok((base64, signature))
    }
}

impl Verifier {
    /// Creates a new `Verifier` from an ed25519 VerifyingKey
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn verify<CLAIMS: Message + Default>(
        &self,
        token: &str,
    ) -> Result<TokenData<CLAIMS>, Error> {
        let (claims, signature) = parse_token(token)?;
        let bytes = claims.to_bytes()?;
        self.verify_signature(&bytes, &signature)?;

        let token_data = bytes.decode_metadata()?;
        let claims = CLAIMS::parse_from_bytes(&token_data.claims)
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        Ok(TokenData {
            valid_until: token_data.valid_until,
            claims,
        })
    }

    pub fn verify_bytes<CLAIMS: Message + Default>(
        &self,
        token: &[u8],
    ) -> Result<TokenData<CLAIMS>, Error> {
        let signed_token = proto::SignedToken::parse_from_bytes(token)
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        let signature =
            Signature::from_slice(&signed_token.signature).map_err(|_| Error::InvalidSignature)?;
        self.key
            .verify(&signed_token.data, &signature)
            .map_err(|_| Error::SignatureMismatch)?;

        let token_data = BytesClaims(signed_token.data).decode_metadata()?;
        let claims = CLAIMS::parse_from_bytes(&token_data.claims)
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        Ok(TokenData {
            valid_until: token_data.valid_until,
            claims,
        })
    }

    pub fn verify_and_check_expiry<CLAIMS: Message + Default>(
        &self,
        token: &str,
    ) -> Result<CLAIMS, Error> {
        let (claims, signature) = parse_token(token)?;
        let bytes = claims.to_bytes()?;
        self.verify_signature(&bytes, &signature)?;

        let token_data = bytes.decode_metadata()?;

        let now = SystemTime::now();
        if now > token_data.valid_until {
            return Result::Err(Error::TokenExpired);
        }

        CLAIMS::parse_from_bytes(&token_data.claims)
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))
    }

    pub fn verify_bytes_and_check_expiry<CLAIMS: Message + Default>(
        &self,
        token: &[u8],
    ) -> Result<CLAIMS, Error> {
        let signed_token = proto::SignedToken::parse_from_bytes(token)
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        let signature =
            Signature::from_slice(&signed_token.signature).map_err(|_| Error::InvalidSignature)?;
        self.key
            .verify(&signed_token.data, &signature)
            .map_err(|_| Error::SignatureMismatch)?;

        let token_data = BytesClaims(signed_token.data).decode_metadata()?;

        let now = SystemTime::now();
        if now > token_data.valid_until {
            return Result::Err(Error::TokenExpired);
        }

        CLAIMS::parse_from_bytes(&token_data.claims)
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))
    }

    fn verify_signature(
        &self,
        bytes: &BytesClaims,
        signature: &Base64Signature,
    ) -> Result<(), Error> {
        let signature = general_purpose::URL_SAFE_NO_PAD
            .decode(signature.0)
            .map_err(|_| Error::InvalidBase64)?;
        let signature =
            Signature::from_slice(signature.as_slice()).map_err(|_| Error::InvalidSignature)?;

        self.key
            .verify(&bytes.0, &signature)
            .map_err(|_| Error::SignatureMismatch)?;
        Ok(())
    }
}

impl<'a> Base64Claims<'a> {
    pub fn to_bytes(&'a self) -> Result<BytesClaims, Error> {
        general_purpose::URL_SAFE_NO_PAD
            .decode(self.0)
            .map(BytesClaims)
            .map_err(|_| Error::InvalidBase64)
    }
}

impl BytesClaims {
    pub fn decode_metadata(&self) -> Result<TokenData<Vec<u8>>, Error> {
        let token = proto::Token::parse_from_bytes(&self.0)
            .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
        let valid_until: SystemTime = token
            .valid_until
            .into_option()
            .ok_or(Error::MissingValidUntil)?
            .try_into()
            .map_err(|_| Error::MissingValidUntil)?;
        Ok(TokenData {
            valid_until,
            claims: token.claims,
        })
    }
}

fn parse_token(token: &str) -> Result<(Base64Claims<'_>, Base64Signature<'_>), Error> {
    let (data, signature) = token.split_once('.').ok_or(Error::InvalidFormat)?;
    Ok((Base64Claims(data), Base64Signature(signature)))
}

pub fn decode<CLAIMS: Message + Default>(token: &str) -> Result<TokenData<CLAIMS>, Error> {
    let (data, _signature) = token.split_once('.').ok_or(Error::InvalidFormat)?;
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| Error::InvalidBase64)?;

    let decoded_metadata = proto::Token::parse_from_bytes(&bytes)
        .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
    let valid_until = decoded_metadata
        .valid_until
        .into_option()
        .ok_or(Error::MissingValidUntil)?
        .try_into()
        .map_err(|_| Error::MissingValidUntil)?;
    let claims = CLAIMS::parse_from_bytes(&decoded_metadata.claims)
        .map_err(|e| Error::ProtobufDecodeError(e.to_string()))?;
    Ok(TokenData {
        valid_until,
        claims,
    })
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidFormat => f.write_str(
                "Invalid Token Format. Expected two string segments seperated by a dot ('.')",
            ),
            Error::InvalidBase64 => f.write_str(
                "A part of the token was not valid base64 (A-Z, a-z, 0-9, -, _, no padding)",
            ),
            Error::InvalidSignature => {
                f.write_str("The signature is not a valid Ed25519 signature")
            }
            Error::SignatureMismatch => f.write_str(
                "The signature does not match the given data (probably the token was manipulated)",
            ),
            Error::ProtobufDecodeError(e) => f.write_fmt(format_args!(
                "The data encoded in the token did not match the expected protobuf format: {e}"
            )),
            Error::MissingValidUntil => {
                f.write_str("The data encoded in the token did not include an expiry time")
            }
            Error::TokenExpired => f.write_str("The token is expired"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use ed25519::pkcs8::DecodePrivateKey;
    use rand::distr::SampleString;
    use serde::Serialize;

    use super::*;
    use crate::generated::pwt as main_proto;
    use crate::jwt;

    mod test_proto {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/generated/mod.rs"
        ));
    }
    use test_proto::test as proto;

    #[derive(Debug, Clone, Serialize)]
    struct Simple {
        some_claim: String,
    }

    fn init_signer() -> Signer {
        let pem = std::fs::read("test_resources/private.pem").unwrap();
        let pem = String::from_utf8(pem).unwrap();
        let key = SigningKey::from_pkcs8_pem(&pem).unwrap();
        Signer { key }
    }

    #[test]
    fn happy_case() {
        let pwt_signer = init_signer();
        let simple = proto::Simple {
            some_claim: "testabcd".to_string(),
            ..Default::default()
        };
        let pwt = pwt_signer.sign(&simple, Duration::from_secs(5));
        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify_and_check_expiry::<proto::Simple>(&pwt),
            Result::Ok(simple)
        );
    }

    #[test]
    fn happy_case_bytes() {
        let pwt_signer = init_signer();
        let simple = proto::Simple {
            some_claim: "testabcd".to_string(),
            ..Default::default()
        };
        let pwt = pwt_signer.sign_to_bytes(&simple, Duration::from_secs(5));
        println!("{}{pwt:?}", pwt.len());
        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify_bytes_and_check_expiry::<proto::Simple>(&pwt),
            Result::Ok(simple)
        );
    }

    #[test]
    fn signature_is_verified_and_prevents_tampering() {
        let pwt_signer = init_signer();
        let proto_token = pwt_signer
            .create_proto_token(
                &proto::Simple {
                    some_claim: "test contents".to_string(),
                    ..Default::default()
                },
                Duration::from_secs(5),
            )
            .unwrap();
        let (_data, signature) = pwt_signer.sign_proto_token(&proto_token).unwrap();
        let other_proto_token = pwt_signer
            .create_proto_token(
                &proto::Simple {
                    some_claim: "tampered contents".to_string(),
                    ..Default::default()
                },
                Duration::from_secs(5),
            )
            .unwrap();
        let (other_data, _) = pwt_signer.sign_proto_token(&other_proto_token).unwrap();

        let tampered_token = format!("{other_data}.{signature}");

        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify::<proto::Simple>(&tampered_token),
            Result::Err(Error::SignatureMismatch)
        );
    }

    #[test]
    fn signature_is_verified_and_prevents_tampering_bytes() {
        let pwt_signer = init_signer();
        let proto_token = pwt_signer
            .create_proto_token(
                &proto::Simple {
                    some_claim: "test contents".to_string(),
                    ..Default::default()
                },
                Duration::from_secs(5),
            )
            .unwrap();

        let data = proto_token.write_to_bytes().expect("Failed to encode");
        let signature = pwt_signer.key.sign(&data);
        let other_proto_token = pwt_signer
            .create_proto_token(
                &proto::Simple {
                    some_claim: "tampered contents".to_string(),
                    ..Default::default()
                },
                Duration::from_secs(5),
            )
            .unwrap();
        let other_data = other_proto_token
            .write_to_bytes()
            .expect("Failed to encode");

        let tampered_token = main_proto::SignedToken {
            data: other_data,
            signature: signature.to_bytes().to_vec(),
            ..Default::default()
        }
        .write_to_bytes()
        .expect("Failed to encode");

        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify_bytes::<proto::Simple>(&tampered_token),
            Result::Err(Error::SignatureMismatch)
        );
    }

    #[test]
    fn invalid_format() {
        let pwt_signer = init_signer();
        assert_eq!(
            pwt_signer.as_verifier().verify::<proto::Simple>("invalid"),
            Result::Err(Error::InvalidFormat)
        );
    }

    #[test]
    fn invalid_base64() {
        let pwt_signer = init_signer();
        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify::<proto::Simple>("invalid.base64"),
            Result::Err(Error::InvalidBase64)
        );
    }

    #[test]
    fn invalid_signature() {
        let pwt_signer = init_signer();
        let base64 = general_purpose::URL_SAFE_NO_PAD.encode("base64");
        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify::<proto::Simple>(&format!("{base64}.{base64}")),
            Result::Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn protobuf_decode_mismatch() {
        let pwt_signer = init_signer();
        let pwt = pwt_signer.sign(
            &proto::Simple {
                some_claim: "test contents".to_string(),
                ..Default::default()
            },
            Duration::from_secs(5),
        );
        let verify = pwt_signer.as_verifier().verify::<proto::Complex>(&pwt);
        if !matches!(verify, Result::Err(Error::ProtobufDecodeError(_))) {
            panic!("Expected ProtobufDecodeError but got {verify:?}");
        }
    }

    #[test]
    fn size_is_smaller_than_jwt() {
        let jwt_signer = jwt::init_jwt_signer();
        let pwt_signer = init_signer();

        let pwt = pwt_signer.sign(
            &proto::Simple {
                some_claim: "test contents".to_string(),
                ..Default::default()
            },
            Duration::from_secs(300),
        );
        println!("{pwt}");
        let jwt = jwt::jwt_encode(
            &jwt_signer,
            Simple {
                some_claim: "test contents".to_string(),
            },
            300,
        );
        let pwt_len = f64::from(u32::try_from(pwt.len()).unwrap());
        let jwt_len = f64::from(u32::try_from(jwt.len()).unwrap());
        assert!(
            pwt_len * 1.2 < jwt_len,
            "{pwt} was not small enough in comparison to {jwt}"
        );
    }

    #[derive(Debug, Clone, Serialize)]
    struct Complex {
        email: String,
        user_name: String,
        user_id: String,
        valid_until: SystemTime,
        roles: Vec<String>,
        nested: Nested,
    }

    #[derive(Debug, Clone, Serialize)]
    struct Nested {
        team_id: String,
        team_name: String,
    }

    #[test]
    fn size_is_smaller_than_jwt_complex() {
        let jwt_signer = jwt::init_jwt_signer();
        let pwt_signer = init_signer();
        let now = SystemTime::now();

        let pwt = pwt_signer.sign(
            &proto::Complex {
                email: "andreas.molitor@andrena.de".to_string(),
                user_name: "Andreas Molitor".to_string(),
                user_id: 123456789,
                roles: vec![
                    proto::Role::ReadFeatureFoo.into(),
                    proto::Role::WriteFeatureFoo.into(),
                    proto::Role::ReadFeatureBar.into(),
                ],
                nested: MessageField::some(proto::Nested {
                    team_id: 3432535236263,
                    team_name: "andrena".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Duration::from_secs(300),
        );
        let jwt = jwt::jwt_encode(
            &jwt_signer,
            Complex {
                email: "andreas.molitor@andrena.de".to_string(),
                user_name: "Andreas Molitor".to_string(),
                user_id: "123456789".to_string(),
                valid_until: (now + Duration::from_secs(5)),
                roles: vec![
                    "ReadFeatureFoo".to_string(),
                    "WriteFeatureFoo".to_string(),
                    "ReadFeatureBar".to_string(),
                ],
                nested: Nested {
                    team_id: "3432535236263".to_string(),
                    team_name: "andrena".to_string(),
                },
            },
            300,
        );
        let pwt_len = f64::from(u32::try_from(pwt.len()).unwrap());
        let jwt_len = f64::from(u32::try_from(jwt.len()).unwrap());
        assert!(
            pwt_len * 2.0 < jwt_len,
            "{pwt} was not small enough in comparison to {jwt}"
        );
    }

    #[test]
    #[ignore] // generate only if specifically requested (with cargo test -- --ignored)
    fn generate_fuzz_outputs() -> Result<(), Box<dyn std::error::Error>> {
        use rand::distr::Alphanumeric;

        let pwt_signer = init_signer();
        let mut fuzz_output = Vec::new();

        for i in 1..100 {
            let random_string: String = Alphanumeric::default().sample_string(&mut rand::rng(), i);
            let pwt = pwt_signer.sign(
                &proto::Simple {
                    some_claim: random_string.clone(),
                    ..Default::default()
                },
                Duration::from_secs(500),
            );
            let pwt_bytes = pwt_signer.sign_to_bytes(
                &proto::Simple {
                    some_claim: random_string.clone(),
                    ..Default::default()
                },
                Duration::from_secs(500),
            );
            let data: TokenData<proto::Simple> = pwt_signer.as_verifier().verify(&pwt)?;
            let timestamp = data
                .valid_until
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();
            let json = serde_json::json!({
                "input": random_string,
                "output": pwt,
                "output_binary": pwt_bytes,
                "timestamp": timestamp
            });
            fuzz_output.push(json);
        }
        let file_contents = serde_json::to_string_pretty(&fuzz_output)?;
        std::fs::create_dir_all("fuzz")?;
        std::fs::write("fuzz/rust.json", file_contents)?;
        Ok(())
    }

    #[test]
    fn try_sign_success() {
        let pwt_signer = init_signer();
        let simple = proto::Simple {
            some_claim: "test content".to_string(),
            ..Default::default()
        };

        // try_sign should succeed with valid input
        let result = pwt_signer.try_sign(&simple, Duration::from_secs(300));
        assert!(result.is_ok());

        // The result should be the same as the regular sign method
        let try_sign_token = result.unwrap();
        let regular_sign_token = pwt_signer.sign(&simple, Duration::from_secs(300));

        // Both tokens should be valid (though not identical due to timestamps)
        assert!(
            pwt_signer
                .as_verifier()
                .verify::<proto::Simple>(&try_sign_token)
                .is_ok()
        );
        assert!(
            pwt_signer
                .as_verifier()
                .verify::<proto::Simple>(&regular_sign_token)
                .is_ok()
        );
    }

    #[test]
    fn try_sign_to_bytes_success() {
        let pwt_signer = init_signer();
        let simple = proto::Simple {
            some_claim: "test content".to_string(),
            ..Default::default()
        };

        // try_sign_to_bytes should succeed with valid input
        let result = pwt_signer.try_sign_to_bytes(&simple, Duration::from_secs(300));
        assert!(result.is_ok());

        // The result should be the same as the regular sign_to_bytes method
        let try_sign_bytes = result.unwrap();
        let regular_sign_bytes = pwt_signer.sign_to_bytes(&simple, Duration::from_secs(300));

        // Both byte arrays should be valid tokens
        assert!(
            pwt_signer
                .as_verifier()
                .verify_bytes::<proto::Simple>(&try_sign_bytes)
                .is_ok()
        );
        assert!(
            pwt_signer
                .as_verifier()
                .verify_bytes::<proto::Simple>(&regular_sign_bytes)
                .is_ok()
        );
    }

    #[test]
    fn try_sign_equivalent_to_sign() {
        let pwt_signer = init_signer();
        let simple = proto::Simple {
            some_claim: "equivalent test".to_string(),
            ..Default::default()
        };

        // Create tokens with both methods (with same duration for comparable timestamps)
        let duration = Duration::from_secs(600);
        let try_result = pwt_signer.try_sign(&simple, duration);

        assert!(try_result.is_ok(), "try_sign should succeed");

        // Both should produce valid, verifiable tokens
        let try_token = try_result.unwrap();
        let regular_token = pwt_signer.sign(&simple, duration);

        let try_decoded = pwt_signer
            .as_verifier()
            .verify::<proto::Simple>(&try_token)
            .unwrap();
        let regular_decoded = pwt_signer
            .as_verifier()
            .verify::<proto::Simple>(&regular_token)
            .unwrap();

        // The claims should be identical
        assert_eq!(
            try_decoded.claims.some_claim,
            regular_decoded.claims.some_claim
        );
        assert_eq!(try_decoded.claims.some_claim, "equivalent test");
    }
}
