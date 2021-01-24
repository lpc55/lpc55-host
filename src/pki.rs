//! Abstraction allowing use of either PKCS1 PEM file or PKCS11 keys
//! for signing data.

use std::convert::{TryFrom, TryInto};
use std::{fmt, fs};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;

// todo: remove
use crate::rot_fingerprints::cert_fingerprint;


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

/// An RSA2k public key
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey(pub rsa::RSAPublicKey);

impl PublicKey {
    pub fn fingerprint(&self) -> Sha256Hash {
        use rsa::PublicKeyParts as _;
        let n = self.0.n();
        let e = self.0.e();

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(n.to_bytes_be());
        hasher.update(e.to_bytes_be());
        let hash = <[u8; 32]>::try_from(hasher.finalize()).unwrap();
        Sha256Hash(hash)
    }
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

    pub fn public_key(&self) -> PublicKey {
        use SigningKey::*;
        PublicKey(match self {
            Pkcs1(key) => {
                key.to_public_key()
            }
            Pkcs11Uri(uri) => {
                let (context, session, object) = uri.identify_object().unwrap();

                use pkcs11::types::{CK_ATTRIBUTE, CKA_MODULUS, CKA_PUBLIC_EXPONENT};

                let /*mut*/ n_buffer = [0u8; 256];  // rust-pkcs11 API is sloppy about mut here; 256B = 2048b is enough for RSA2k keys
                let /*mut*/ e_buffer = [0u8; 3];    // always 0x10001 = u16::MAX + 2 anyway
                let mut n_attribute = CK_ATTRIBUTE::new(CKA_MODULUS);
                n_attribute.set_biginteger(&n_buffer);
                let mut e_attribute = CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT);
                e_attribute.set_biginteger(&e_buffer);
                let mut template = vec![n_attribute, e_attribute];

                let (rv, attributes) = context.get_attribute_value(session, object, &mut template).unwrap();
                assert_eq!(rv, 0);
                let n = attributes[0].get_biginteger().unwrap();
                let e = attributes[1].get_biginteger().unwrap();
                assert_eq!(n.bits(), 2048);
                // dbg!(n.to_str_radix(10));
                assert_eq!(e.to_str_radix(10), "65537");

                // https://github.com/mheese/rust-pkcs11/issues/44
                let n = rsa::BigUint::from_bytes_be(&n.to_bytes_le());
                let e = rsa::BigUint::from_bytes_be(&e.to_bytes_le());
                let public_key = rsa::RSAPublicKey::new(n, e).unwrap();
                public_key
            }
        })
    }

    pub fn fingerprint(&self) -> Sha256Hash {
        self.public_key().fingerprint()
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

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CertificateSlot(usize);

impl From<usize> for CertificateSlot {
    /// panics if i > 3
    fn from(i: usize) -> Self {
        if i <= 3 {
            Self(i)
        } else {
            panic!("Index {} not one of 0, 1, 2, 3", i);
        }
    }
}

impl From<CertificateSlot> for usize {
    /// panics if i > 3
    fn from(i: CertificateSlot) -> usize {
        i.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CertificateSource {
    X509DerFile(std::path::PathBuf),
    Pkcs11Uri(std::string::String),
    // RawDer(Vec<u8>),
}

impl TryFrom<&'_ str> for CertificateSource {
    type Error = anyhow::Error;
    fn try_from(uri: &str) -> anyhow::Result<Self> {
        let (scheme, content) = split_once(uri, ':').unwrap();
        let key_source = match scheme {
            "file" => CertificateSource::X509DerFile(std::path::PathBuf::from(content)),
            "pkcs11" => CertificateSource::Pkcs11Uri(uri.to_string()),
            _ => return Err(anyhow::anyhow!("only file and pkcs11 certificate URIs supported")),
        };
        Ok(key_source)
    }
}

#[derive(Clone, Debug)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    // todo: consider offering pkcs11-uri here too
    pub fn try_from(source: &CertificateSource) -> Result<Self> {
        use CertificateSource::*;
        let der = match source {
            X509DerFile(filename) => fs::read(filename)?,
            _ => todo!() ,
        };
        Certificate::try_from_der(&der)
    }

    /// Checks certificate is valid, and public key is RSA.
    pub fn try_from_der(der: &[u8]) -> Result<Self> {
        // implicitly checks public key is RSA
        let _ = cert_fingerprint(X509Certificate::from_der(der)?.1)?;
        Ok(Self { der: Vec::from(der) })
    }

    pub fn certificate(&self) -> X509Certificate<'_> {
        // no panic, DER is verified in constructor
        X509Certificate::from_der(&self.der).unwrap().1
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn public_key(&self) -> PublicKey {
        let spki = self.certificate().tbs_certificate.subject_pki;
        assert_eq!(oid_registry::OID_PKCS1_RSAENCRYPTION, spki.algorithm.algorithm);
        PublicKey(rsa::RSAPublicKey::from_pkcs1(&spki.subject_public_key.data).unwrap())
    }

    pub fn fingerprint(&self) -> Sha256Hash {
        // no panic, DER is verified in constructor
        Sha256Hash(cert_fingerprint(self.certificate()).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct Certificates {
    certificates: [Certificate; 4],
}

impl Certificates {
    // todo: consider using pkcs11-uri here too
    pub fn try_from(sources: &[CertificateSource; 4]) -> Result<Self> {
        Ok(Self { certificates: [
            Certificate::try_from(&sources[0])?,
            Certificate::try_from(&sources[1])?,
            Certificate::try_from(&sources[2])?,
            Certificate::try_from(&sources[3])?,
        ] })
    }

    /// Checks certificates are valid, and public keys are all RSA.
    pub fn try_from_ders(certificate_ders: [Vec<u8>; 4]) -> Result<Self> {
        Ok(Self { certificates: [
            Certificate::try_from_der(&certificate_ders[0])?,
            Certificate::try_from_der(&certificate_ders[1])?,
            Certificate::try_from_der(&certificate_ders[2])?,
            Certificate::try_from_der(&certificate_ders[3])?,
        ] })
    }

    pub fn index_of(&self, public_key: PublicKey) -> Result<CertificateSlot> {
        for i in 0..4 {
            let slot = i.into();
            if public_key == self.certificate(slot).public_key() {
                return Ok(slot)
            }
        }
        Err(anyhow::anyhow!("no matching certificate found for public key!"))
    }

    pub fn certificate(&self, i: CertificateSlot) -> &Certificate {
        &self.certificates[usize::from(i)]
    }

    pub fn certificate_der(&self, i: CertificateSlot) -> &[u8] {
        self.certificates[usize::from(i)].der()
    }

    pub fn fingerprints(&self) -> [Sha256Hash; 4] {
        // array_map when? :)
        [
            self.certificates[0].fingerprint(),
            self.certificates[1].fingerprint(),
            self.certificates[2].fingerprint(),
            self.certificates[3].fingerprint(),
        ]
    }

    pub fn fingerprint(&self) -> Sha256Hash {
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        for fingerprint in self.fingerprints().iter() {
            hash.update(&fingerprint);
        }
        let hash = <[u8; 32]>::try_from(hash.finalize()).unwrap();
        Sha256Hash(hash)
    }
}


#[derive(Clone, Copy, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Sha256Hash(pub [u8; 32]);
impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes(&self.0, f)
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Sha256Hash {
    fn from(array: [u8; 32]) -> Self {
        Sha256Hash(array)
    }
}

pub(crate) fn format_bytes(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    // let l = bytes.len();
    let empty = bytes.iter().all(|&byte| byte == 0);
    if empty {
        // return f.write_fmt(format_args!("<all zero>"));
        return f.write_fmt(format_args!("∅"));
    }

    for byte in bytes.iter() {
        f.write_fmt(format_args!("{:02X} ", byte))?;
    }
    Ok(())
    // let info = if empty { "empty" } else { "non-empty" };

    // f.write_fmt(format_args!(
    //     "'{:02x} {:02x} {:02x} (...) {:02x} {:02x} {:02x} ({})'",
    //     bytes[0], bytes[1], bytes[3],
    //     bytes[l-3], bytes[l-2], bytes[l-1],
    //     info,
    // ))
}


