//! This crate contains methods to deal with SSH keys, as defined in
//! crate Russh. This includes in particular various functions for
//! opening key files, deciphering encrypted keys, and dealing with
//! agents.
//!
//! The following example shows how to do all these in a single example:
//! start and SSH agent server, connect to it with a client, decipher
//! an encrypted ED25519 private key (the password is `b"blabla"`), send it to
//! the agent, and ask the agent to sign a piece of data
//! (`b"Please sign this"`, below).
//!
//!```
//! use russh::keys::*;
//! use futures::Future;
//!
//! #[derive(Clone)]
//! struct X{}
//! impl agent::server::Agent for X {
//!     fn confirm(self, _: std::sync::Arc<PrivateKey>) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
//!         Box::new(futures::future::ready((self, true)))
//!     }
//! }
//!
//! const PKCS8_ENCRYPTED: &'static str = "-----REMOVED TEST PRIVATE KEY-----\n";
//!
//! #[cfg(unix)]
//! fn main() {
//!    env_logger::try_init().unwrap_or(());
//!    let dir = tempfile::tempdir().unwrap();
//!    let agent_path = dir.path().join("agent");
//!
//!    let mut core = tokio::runtime::Runtime::new().unwrap();
//!    let agent_path_ = agent_path.clone();
//!    // Starting a server
//!    core.spawn(async move {
//!        let mut listener = tokio::net::UnixListener::bind(&agent_path_)
//!            .unwrap();
//!        russh::keys::agent::server::serve(tokio_stream::wrappers::UnixListenerStream::new(listener), X {}).await
//!    });
//!    let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
//!    let public = key.public_key().clone();
//!    core.block_on(async move {
//!        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
//!        let mut client = agent::client::AgentClient::connect(stream);
//!        client.add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }]).await?;
//!        client.request_identities().await?;
//!        let buf = b"signed message";
//!        let sig = client.sign_request(&public, None, russh_cryptovec::CryptoVec::from_slice(&buf[..])).await.unwrap();
//!        // Here, `sig` is encoded in a format usable internally by the SSH protocol.
//!        Ok::<(), Error>(())
//!    }).unwrap()
//! }
//!
//! #[cfg(not(unix))]
//! fn main() {}
//!
//! ```

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::string::FromUtf8Error;

use aes::cipher::block_padding::UnpadError;
use aes::cipher::inout::PadError;
use data_encoding::BASE64_MIME;
use thiserror::Error;

use crate::helpers::EncodedExt;

pub mod key;
pub use key::PrivateKeyWithHashAlg;

mod format;
pub use format::*;
// Reexports
pub use signature;
pub use ssh_encoding;
pub use ssh_key::{self, Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PublicKey};

/// OpenSSH agent protocol implementation
pub mod agent;

#[cfg(not(target_arch = "wasm32"))]
pub mod known_hosts;

#[cfg(not(target_arch = "wasm32"))]
pub use known_hosts::{check_known_hosts, check_known_hosts_path};

#[derive(Debug, Error)]
pub enum Error {
    /// The key could not be read, for an unknown reason
    #[error("Could not read key")]
    CouldNotReadKey,
    /// The type of the key is unsupported
    #[error("Unsupported key type {}", key_type_string)]
    UnsupportedKeyType {
        key_type_string: String,
        key_type_raw: Vec<u8>,
    },
    /// The type of the key is unsupported
    #[error("Invalid Ed25519 key data")]
    Ed25519KeyError(#[from] ed25519_dalek::SignatureError),
    /// The type of the key is unsupported
    #[error("Invalid ECDSA key data")]
    EcdsaKeyError(#[from] p256::elliptic_curve::Error),
    /// The key is encrypted (should supply a password?)
    #[error("The key is encrypted")]
    KeyIsEncrypted,
    /// The key contents are inconsistent
    #[error("The key is corrupt")]
    KeyIsCorrupt,
    /// Home directory could not be found
    #[error("No home directory found")]
    NoHomeDir,
    /// The server key has changed
    #[error("The server key changed at line {}", line)]
    KeyChanged { line: usize },
    /// The key uses an unsupported algorithm
    #[error("Unknown key algorithm: {0}")]
    UnknownAlgorithm(::pkcs8::ObjectIdentifier),
    /// Index out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// Unknown signature type
    #[error("Unknown signature type: {}", sig_type)]
    UnknownSignatureType { sig_type: String },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid parameters")]
    InvalidParameters,
    /// Agent protocol error
    #[error("Agent protocol error")]
    AgentProtocolError,
    #[error("Agent failure")]
    AgentFailure,
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[cfg(feature = "rsa")]
    #[error("Rsa: {0}")]
    Rsa(#[from] rsa::Error),

    #[error(transparent)]
    Pad(#[from] PadError),

    #[error(transparent)]
    Unpad(#[from] UnpadError),

    #[error("Base64 decoding error: {0}")]
    Decode(#[from] data_encoding::DecodeError),
    #[error("Der: {0}")]
    Der(#[from] der::Error),
    #[error("Spki: {0}")]
    Spki(#[from] spki::Error),
    #[cfg(feature = "rsa")]
    #[error("Pkcs1: {0}")]
    Pkcs1(#[from] pkcs1::Error),
    #[error("Pkcs8: {0}")]
    Pkcs8(#[from] ::pkcs8::Error),
    #[error("Sec1: {0}")]
    Sec1(#[from] sec1::Error),

    #[error("SshKey: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("SshEncoding: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    #[error("Environment variable `{0}` not found")]
    EnvVar(&'static str),
    #[error(
        "Unable to connect to ssh-agent. The environment variable `SSH_AUTH_SOCK` was set, but it \
         points to a nonexistent file or directory."
    )]
    BadAuthSock,

    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),

    #[error("ASN1 decoding error: {0}")]
    #[cfg(feature = "legacy-ed25519-pkcs8-parser")]
    LegacyASN1(::yasna::ASN1Error),

    #[cfg(windows)]
    #[error("Pageant: {0}")]
    Pageant(#[from] pageant::Error),
}

#[cfg(feature = "legacy-ed25519-pkcs8-parser")]
impl From<yasna::ASN1Error> for Error {
    fn from(e: yasna::ASN1Error) -> Error {
        Error::LegacyASN1(e)
    }
}

/// Load a public key from a file. Ed25519, EC-DSA and RSA keys are supported.
///
/// ```no_run
/// russh::keys::load_public_key("../files/id_ed25519.pub").unwrap();
/// ```
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<ssh_key::PublicKey, Error> {
    let mut pubkey = String::new();
    let mut file = File::open(path.as_ref())?;
    file.read_to_string(&mut pubkey)?;

    let mut split = pubkey.split_whitespace();
    match (split.next(), split.next()) {
        (Some(_), Some(key)) => parse_public_key_base64(key),
        (Some(key), None) => parse_public_key_base64(key),
        _ => Err(Error::CouldNotReadKey),
    }
}

/// Reads a public key from the standard encoding. In some cases, the
/// encoding is prefixed with a key type identifier and a space (such
/// as `ssh-ed25519 AAAAC3N...`).
///
/// ```
/// russh::keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").is_ok();
/// ```
pub fn parse_public_key_base64(key: &str) -> Result<ssh_key::PublicKey, Error> {
    let base = BASE64_MIME.decode(key.as_bytes())?;
    key::parse_public_key(&base)
}

pub trait PublicKeyBase64 {
    /// Create the base64 part of the public key blob.
    fn public_key_bytes(&self) -> Vec<u8>;
    fn public_key_base64(&self) -> String {
        let mut s = BASE64_MIME.encode(&self.public_key_bytes());
        assert_eq!(s.pop(), Some('\n'));
        assert_eq!(s.pop(), Some('\r'));
        s.replace("\r\n", "")
    }
}

impl PublicKeyBase64 for ssh_key::PublicKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.key_data().encoded().unwrap_or_default()
    }
}

impl PublicKeyBase64 for PrivateKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key().public_key_bytes()
    }
}

/// Load a secret key, deciphering it with the supplied password if necessary.
pub fn load_secret_key<P: AsRef<Path>>(
    secret_: P,
    password: Option<&str>,
) -> Result<PrivateKey, Error> {
    let mut secret_file = std::fs::File::open(secret_)?;
    let mut secret = String::new();
    secret_file.read_to_string(&mut secret)?;
    decode_secret_key(&secret, password)
}

/// Load a openssh certificate
pub fn load_openssh_certificate<P: AsRef<Path>>(cert_: P) -> Result<Certificate, ssh_key::Error> {
    let mut cert_file = std::fs::File::open(cert_)?;
    let mut cert = String::new();
    cert_file.read_to_string(&mut cert)?;

    Certificate::from_openssh(&cert)
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '/'
        || c == '+'
        || c == '='
}

#[cfg(test)]
mod test {

    #[cfg(unix)]
    use futures::Future;

    use super::*;
    use crate::keys::key::PublicKeyExt;

    const ED25519_KEY: &str = "-----REMOVED TEST PRIVATE KEY-----";

    // password is 'test'
    const ED25519_AESCTR_KEY: &str = "-----REMOVED TEST PRIVATE KEY-----";

    #[cfg(feature = "rsa")]
    const RSA_KEY: &str = "-----REMOVED TEST PRIVATE KEY-----";

    #[test]
    fn test_decode_ed25519_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
    }

    #[test]
    fn test_decode_ed25519_aesctr_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(ED25519_AESCTR_KEY, Some("test")).unwrap();
    }

    // Key from RFC 8410 Section 10.3. This is a key using PrivateKeyInfo structure.
    const RFC8410_ED25519_PRIVATE_ONLY_KEY: &str = "-----REMOVED TEST PRIVATE KEY-----";

    #[test]
    fn test_decode_rfc8410_ed25519_private_only_key() {
        env_logger::try_init().unwrap_or(());
        assert!(
            decode_secret_key(RFC8410_ED25519_PRIVATE_ONLY_KEY, None)
                .unwrap()
                .algorithm()
                == ssh_key::Algorithm::Ed25519,
        );
        // We always encode public key, skip test_decode_encode_symmetry.
    }

    // Key from RFC 8410 Section 10.3. This is a key using OneAsymmetricKey structure.
    const RFC8410_ED25519_PRIVATE_PUBLIC_KEY: &str = "-----REMOVED TEST PRIVATE KEY-----";

    #[test]
    fn test_decode_rfc8410_ed25519_private_public_key() {
        env_logger::try_init().unwrap_or(());
        assert!(
            decode_secret_key(RFC8410_ED25519_PRIVATE_PUBLIC_KEY, None)
                .unwrap()
                .algorithm()
                == ssh_key::Algorithm::Ed25519,
        );
        // We can't encode attributes, skip test_decode_encode_symmetry.
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_decode_rsa_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(RSA_KEY, None).unwrap();
    }

    #[test]
    fn test_decode_openssh_p256_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 256 -m rfc4716 -f $file
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256
                },
        );
    }

    #[test]
    fn test_decode_openssh_p384_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 384 -m rfc4716 -f $file
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384
                },
        );
    }

    #[test]
    fn test_decode_openssh_p521_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 521 -m rfc4716 -f $file
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP521
                },
        );
    }

    #[test]
    fn test_fingerprint() {
        let key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ",
        )
        .unwrap();
        assert_eq!(
            format!("{}", key.fingerprint(ssh_key::HashAlg::Sha256)),
            "SHA256:ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    #[test]
    fn test_parse_p256_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxBTpMIGvo7CnordO7wP0QQRqpBwUjOLl4eMhfucfE1sjTYyK5wmTl1UqoSDS1PtRVTBdl+0+9pquFb46U7fwg=";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256
                },
        );
    }

    #[test]
    fn test_parse_p384_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBVFgxJxpCaAALZG/S5BHT8/IUQ5mfuKaj7Av9g7Jw59fBEGHfPBz1wFtHGYw5bdLmfVZTIDfogDid5zqJeAKr1AcD06DKTXDzd2EpUjqeLfQ5b3erHuX758fgu/pSDGRA==";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384
                }
        );
    }

    #[test]
    fn test_parse_p521_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAQepXEpOrzlX22r4E5zEHjhHWeZUe//zaevTanOWRBnnaCGWJFGCdjeAbNOuAmLtXc+HZdJTCZGREeSLSrpJa71QDCgZl0N7DkDUanCpHZJe/DCK6qwtHYbEMn28iLMlGCOrCIa060EyJHbp1xcJx4I1SKj/f/fm3DhhID/do6zyf8Cg==";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP521
                }
        );
    }

    #[test]
    fn test_srhb() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAB3NzaC1yc2EAAAADAQABAAACAQC0Xtz3tSNgbUQAXem4d+d6hMx7S8Nwm/DOO2AWyWCru+n/+jQ7wz2b5+3oG2+7GbWZNGj8HCc6wJSA3jUsgv1N6PImIWclD14qvoqY3Dea1J0CJgXnnM1xKzBz9C6pDHGvdtySg+yzEO41Xt4u7HFn4Zx5SGuI2NBsF5mtMLZXSi33jCIWVIkrJVd7sZaY8jiqeVZBB/UvkLPWewGVuSXZHT84pNw4+S0Rh6P6zdNutK+JbeuO+5Bav4h9iw4t2sdRkEiWg/AdMoSKmo97Gigq2mKdW12ivnXxz3VfxrCgYJj9WwaUUWSfnAju5SiNly0cTEAN4dJ7yB0mfLKope1kRhPsNaOuUmMUqlu/hBDM/luOCzNjyVJ+0LLB7SV5vOiV7xkVd4KbEGKou8eeCR3yjFazUe/D1pjYPssPL8cJhTSuMc+/UC9zD8yeEZhB9V+vW4NMUR+lh5+XeOzenl65lWYd/nBZXLBbpUMf1AOfbz65xluwCxr2D2lj46iApSIpvE63i3LzFkbGl9GdUiuZJLMFJzOWdhGGc97cB5OVyf8umZLqMHjaImxHEHrnPh1MOVpv87HYJtSBEsN4/omINCMZrk++CRYAIRKRpPKFWV7NQHcvw3m7XLR3KaTYe+0/MINIZwGdou9fLUU3zSd521vDjA/weasH0CyDHq7sZw==";

        parse_public_key_base64(key).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_nikao() {
        env_logger::try_init().unwrap_or(());
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        decode_secret_key(key, None).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_decode_pkcs8_rsa_secret_key() {
        // Generated using: ssh-keygen -t rsa -b 1024 -m pkcs8 -f $file
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        assert!(decode_secret_key(key, None).unwrap().algorithm().is_rsa());
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p256_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 256 -m pkcs8 -f $file
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256
                },
        );
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p384_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 384 -m pkcs8 -f $file
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384
                },
        );
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p521_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 521 -m pkcs8 -f $file
        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        assert!(
            decode_secret_key(key, None).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP521
                },
        );
        test_decode_encode_symmetry(key);
    }

    #[test]
    #[cfg(feature = "legacy-ed25519-pkcs8-parser")]
    fn test_decode_pkcs8_ed25519_generated_by_russh_0_43() -> Result<(), crate::keys::Error> {
        // Generated by russh 0.43
        let key = "-----REMOVED TEST PRIVATE KEY-----
";

        assert!(decode_secret_key(key, None)?.algorithm() == ssh_key::Algorithm::Ed25519,);

        let k = decode_secret_key(key, None)?;
        let inner = k.key_data().ed25519().unwrap();

        assert_eq!(
            &inner.private.to_bytes(),
            &[
                17, 240, 225, 197, 207, 164, 104, 0, 248, 167, 111, 60, 94, 96, 198, 188, 204, 47,
                234, 26, 223, 36, 36, 208, 156, 200, 109, 107, 230, 168, 206, 71
            ]
        );

        Ok(())
    }

    fn test_decode_encode_symmetry(key: &str) {
        let original_key_bytes = data_encoding::BASE64_MIME
            .decode(
                key.lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<Vec<&str>>()
                    .join("")
                    .as_bytes(),
            )
            .unwrap();
        let decoded_key = decode_secret_key(key, None).unwrap();
        let encoded_key_bytes = pkcs8::encode_pkcs8(&decoded_key).unwrap();
        assert_eq!(original_key_bytes, encoded_key_bytes);
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_o01eg() {
        env_logger::try_init().unwrap_or(());

        let key = "-----REMOVED TEST PRIVATE KEY-----
";
        decode_secret_key(key, Some("12345")).unwrap();
    }

    #[cfg(feature = "rsa")]
    pub const PKCS8_RSA: &str = "-----REMOVED TEST PRIVATE KEY-----
";

    #[cfg(feature = "rsa")]
    #[test]
    fn test_pkcs8() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_RSA, Some("blabla")).unwrap();
    }

    #[cfg(feature = "rsa")]
    const PKCS8_ENCRYPTED: &str = "-----REMOVED TEST PRIVATE KEY-----";

    #[test]
    fn test_gpg() {
        env_logger::try_init().unwrap_or(());
        let key = [
            0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 129, 0, 163,
            72, 59, 242, 4, 248, 139, 217, 57, 126, 18, 195, 170, 3, 94, 154, 9, 150, 89, 171, 236,
            192, 178, 185, 149, 73, 210, 121, 95, 126, 225, 209, 199, 208, 89, 130, 175, 229, 163,
            102, 176, 155, 69, 199, 155, 71, 214, 170, 61, 202, 2, 207, 66, 198, 147, 65, 10, 176,
            20, 105, 197, 133, 101, 126, 193, 252, 245, 254, 182, 14, 250, 118, 113, 18, 220, 38,
            220, 75, 247, 50, 163, 39, 2, 61, 62, 28, 79, 199, 238, 189, 33, 194, 190, 22, 87, 91,
            1, 215, 115, 99, 138, 124, 197, 127, 237, 228, 170, 42, 25, 117, 1, 106, 36, 54, 163,
            163, 207, 129, 133, 133, 28, 185, 170, 217, 12, 37, 113, 181, 182, 180, 178, 23, 198,
            233, 31, 214, 226, 114, 146, 74, 205, 177, 82, 232, 238, 165, 44, 5, 250, 150, 236, 45,
            30, 189, 254, 118, 55, 154, 21, 20, 184, 235, 223, 5, 20, 132, 249, 147, 179, 88, 146,
            6, 100, 229, 200, 221, 157, 135, 203, 57, 204, 43, 27, 58, 85, 54, 219, 138, 18, 37,
            80, 106, 182, 95, 124, 140, 90, 29, 48, 193, 112, 19, 53, 84, 201, 153, 52, 249, 15,
            41, 5, 11, 147, 18, 8, 27, 31, 114, 45, 224, 118, 111, 176, 86, 88, 23, 150, 184, 252,
            128, 52, 228, 90, 30, 34, 135, 234, 123, 28, 239, 90, 202, 239, 188, 175, 8, 141, 80,
            59, 194, 80, 43, 205, 34, 137, 45, 140, 244, 181, 182, 229, 247, 94, 216, 115, 173,
            107, 184, 170, 102, 78, 249, 4, 186, 234, 169, 148, 98, 128, 33, 115, 232, 126, 84, 76,
            222, 145, 90, 58, 1, 4, 163, 243, 93, 215, 154, 205, 152, 178, 109, 241, 197, 82, 148,
            222, 78, 44, 193, 248, 212, 157, 118, 217, 75, 211, 23, 229, 121, 28, 180, 208, 173,
            204, 14, 111, 226, 25, 163, 220, 95, 78, 175, 189, 168, 67, 159, 179, 176, 200, 150,
            202, 248, 174, 109, 25, 89, 176, 220, 226, 208, 187, 84, 169, 157, 14, 88, 217, 221,
            117, 254, 51, 45, 93, 184, 80, 225, 158, 29, 76, 38, 69, 72, 71, 76, 50, 191, 210, 95,
            152, 175, 26, 207, 91, 7,
        ];
        ssh_key::PublicKey::decode(&key).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_pkcs8_encrypted() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
    }

    #[cfg(unix)]
    async fn test_client_agent(key: PrivateKey) -> Result<(), Box<dyn std::error::Error>> {
        env_logger::try_init().unwrap_or(());
        use std::process::Stdio;

        let dir = tempfile::tempdir()?;
        let agent_path = dir.path().join("agent");
        let mut agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let public = key.public_key();
        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
        let mut client = agent::client::AgentClient::connect(stream);
        client.add_identity(&key, &[]).await?;
        client.request_identities().await?;
        let buf = russh_cryptovec::CryptoVec::from_slice(b"blabla");
        let len = buf.len();
        let buf = client
            .sign_request(public, Some(HashAlg::Sha256), buf)
            .await
            .unwrap();
        let (a, b) = buf.split_at(len);

        match key.public_key().key_data() {
            ssh_key::public::KeyData::Ed25519 { .. } => {
                let sig = &b[b.len() - 64..];
                let sig = ssh_key::Signature::new(key.algorithm(), sig)?;
                use signature::Verifier;
                assert!(Verifier::verify(public, a, &sig).is_ok());
            }
            ssh_key::public::KeyData::Ecdsa { .. } => {}
            _ => {}
        }

        agent.kill().await?;
        agent.wait().await?;

        Ok(())
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_client_agent_ed25519() {
        let key = decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_client_agent_rsa() {
        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_client_agent_openssh_rsa() {
        let key = decode_secret_key(RSA_KEY, None).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[test]
    #[cfg(all(unix, feature = "rsa"))]
    fn test_agent() {
        env_logger::try_init().unwrap_or(());
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");

        let core = tokio::runtime::Runtime::new().unwrap();
        use agent;
        use signature::Verifier;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {
            fn confirm(
                self,
                _: std::sync::Arc<PrivateKey>,
            ) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
                Box::new(futures::future::ready((self, true)))
            }
        }
        let agent_path_ = agent_path.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        core.spawn(async move {
            let mut listener = tokio::net::UnixListener::bind(&agent_path_).unwrap();
            let _ = tx.send(());
            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });

        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        core.block_on(async move {
            let public = key.public_key();
            // make sure the listener created the file handle
            rx.await.unwrap();
            let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
            let mut client = agent::client::AgentClient::connect(stream);
            client
                .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }])
                .await
                .unwrap();
            client.request_identities().await.unwrap();
            let buf = russh_cryptovec::CryptoVec::from_slice(b"blabla");
            let len = buf.len();
            let buf = client.sign_request(public, None, buf).await.unwrap();
            let (a, b) = buf.split_at(len);
            if let ssh_key::public::KeyData::Ed25519 { .. } = public.key_data() {
                let sig = &b[b.len() - 64..];
                let sig = ssh_key::Signature::new(key.algorithm(), sig).unwrap();
                assert!(Verifier::verify(public, a, &sig).is_ok());
            }
        })
    }

    #[cfg(unix)]
    struct Incoming<'a> {
        listener: &'a mut tokio::net::UnixListener,
    }

    #[cfg(unix)]
    impl futures::stream::Stream for Incoming<'_> {
        type Item = Result<tokio::net::UnixStream, std::io::Error>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let (sock, _addr) = futures::ready!(self.get_mut().listener.poll_accept(cx))?;
            std::task::Poll::Ready(Some(Ok(sock)))
        }
    }
}
