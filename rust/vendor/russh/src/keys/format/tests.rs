use super::decode_secret_key;

#[test]
fn test_ec_private_key() {
    let key = r#"-----REMOVED TEST PRIVATE KEY-----"#;
    decode_secret_key(&key, None).unwrap();
}
