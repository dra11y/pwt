use std::time::{Duration, SystemTime};

use protobuf::MessageField;
use pwt::Signer;
use serde::{Deserialize, Serialize};

mod jwt {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/benches/jwt.rs"));
}

// Import the test protobuf types
mod test_proto {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/generated/mod.rs"
    ));
}
use test_proto::test as proto;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Simple {
    some_claim: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Complex {
    email: String,
    user_name: String,
    user_id: String,
    valid_until: std::time::SystemTime,
    roles: Vec<String>,
    nested: Nested,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Nested {
    team_id: String,
    team_name: String,
}

fn init_pwt_signer() -> Signer {
    use pwt::ed25519::pkcs8::DecodePrivateKey;
    let pem = std::fs::read("tests/fixtures/private.pem").unwrap();
    let pem = String::from_utf8(pem).unwrap();
    let key = pwt::ed25519::SigningKey::from_pkcs8_pem(&pem).unwrap();
    Signer::new(key)
}

#[test]
fn pwt_is_smaller_than_jwt_simple() {
    let jwt_signer = jwt::init_jwt_signer();
    let pwt_signer = init_pwt_signer();

    let pwt = pwt_signer.sign(
        &proto::Simple {
            some_claim: "test contents".to_string(),
            ..Default::default()
        },
        Duration::from_secs(300),
    );
    let jwt = jwt::jwt_encode(
        &jwt_signer,
        Simple {
            some_claim: "test contents".to_string(),
        },
        300,
    );

    let pwt_len = pwt.len();
    let jwt_len = jwt.len();

    println!("PWT: {} chars: {}", pwt_len, pwt);
    println!("JWT: {} chars: {}", jwt_len, jwt);
    println!(
        "PWT is {:.1}% the size of JWT",
        (pwt_len as f64 / jwt_len as f64) * 100.0
    );

    assert!(
        (pwt_len as f64) * 1.2 < jwt_len as f64,
        "PWT ({} chars) should be at least 20% smaller than JWT ({} chars)",
        pwt_len,
        jwt_len
    );
}

#[test]
fn pwt_is_smaller_than_jwt_complex() {
    let jwt_signer = jwt::init_jwt_signer();
    let pwt_signer = init_pwt_signer();
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

    let pwt_len = pwt.len();
    let jwt_len = jwt.len();

    println!("Complex PWT: {} chars", pwt_len);
    println!("Complex JWT: {} chars", jwt_len);
    println!(
        "PWT is {:.1}% the size of JWT",
        (pwt_len as f64 / jwt_len as f64) * 100.0
    );

    assert!(
        (pwt_len as f64) * 2.0 < jwt_len as f64,
        "PWT ({} chars) should be at least 50% smaller than JWT ({} chars)",
        pwt_len,
        jwt_len
    );
}
