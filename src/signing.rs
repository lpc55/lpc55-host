//! Abstraction allowing use of either keys in files or PKCS11 keys
//! for signing data.
//!
//! TODO: compare/contrast https://github.com/iqlusioninc/signatory

use std::convert::{TryFrom, TryInto};

#[derive(Clone, Debug, PartialEq)]
pub enum SigningKeySource {
    Pkcs1PemFile(std::path::PathBuf),
    Pkcs11Uri(std::string::String),
}

pub fn split_once(s: &str, delimiter: char) -> Option<(&str, &str)> {
    let i = s.find(delimiter)?;
    Some((&s[..i], &s[i + 1..]))
}


impl TryFrom<&'_ str> for SigningKeySource {
    type Error = anyhow::Error;
    fn try_from(uri: &str) -> anyhow::Result<Self> {
        let (scheme, content) = split_once(uri, ':').unwrap();
        let key_source = match scheme {
            "file" => SigningKeySource::Pkcs1PemFile(std::path::PathBuf::from(content)),
            "pkcs11" => SigningKeySource::Pkcs11Uri(uri.to_string()),
            _ => return Err(anyhow::anyhow!("only file and pkcs11 secret key URIs supported")),
        };
        Ok(key_source)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SigningKey {
    Pkcs1(rsa::RSAPrivateKey),
    Pkcs11Uri(pkcs11_uri::Pkcs11Uri),
}

const SIGNATURE_LENGTH: usize = 256;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl SigningKey {
    pub fn try_from_uri(uri: &str) -> anyhow::Result<Self> {
        let source = SigningKeySource::try_from(uri)?;
        Self::try_load(&source)
    }

    pub fn try_load(source: &SigningKeySource) -> anyhow::Result<SigningKey> {
        use SigningKeySource::*;
        Ok(match source {
            Pkcs1PemFile(path) => {
                let pem = std::fs::read_to_string(path)?;
                // do this instead:
                // https://docs.rs/rsa/0.3.0/rsa/struct.RSAPrivateKey.html?search=#example
                let der = pem_parser::pem_to_der(&pem);
                let key = rsa::RSAPrivateKey::from_pkcs1(&der)?;
                SigningKey::Pkcs1(key)
            }
            Pkcs11Uri(uri) => {
                let uri = pkcs11_uri::Pkcs11Uri::try_from(uri)?;
                SigningKey::Pkcs11Uri(uri)
            }
        })
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        use SigningKey::*;
        let signature = match self {
            Pkcs1(key) => {
                let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));

                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                let hashed_data = hasher.finalize();
                let signature = key.sign(padding_scheme, &hashed_data).expect("signatures work");
                signature
            }
            Pkcs11Uri(uri) => {
                let (context, session, object) = uri.identify_object().unwrap();

                //  CKM_SHA256_RSA_PKCS
                let mechanism = pkcs11::types::CK_MECHANISM {
                    mechanism: pkcs11::types::CKM_SHA256_RSA_PKCS,
                    // mechanism: pkcs11::types::CKM_RSA_PKCS,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                };

                // now do a signature, assuming this is an RSA key
                context.sign_init(session, &mechanism, object).unwrap();
                let signature = context.sign(session, data).unwrap();
                signature
            }
        };
        assert_eq!(256, signature.len());
        let mut array = [0u8; SIGNATURE_LENGTH];
        array.copy_from_slice(&signature);
        Signature(array)
    }
}

impl<'a> core::convert::TryFrom<&'a [u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(signature::Error::new());
        }
        let mut array = [0u8; SIGNATURE_LENGTH];
        array.copy_from_slice(bytes);
        Ok(Signature(array))
    }
}

impl signature::Signature for Signature {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        bytes.try_into()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl signature::Signer<Signature> for SigningKey {
    fn try_sign(&self, data: &[u8]) -> Result<Signature, signature::Error> {
        Ok(self.sign(data))
    }
}
