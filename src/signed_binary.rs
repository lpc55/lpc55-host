use core::convert::TryFrom;
use std::fs;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;

use crate::protected_flash::Sha256Hash;
use crate::rot_fingerprints::cert_fingerprint;
use crate::secure_binary::Config;
use crate::signature::SigningKey;
use crate::util::word_padded;

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

#[derive(Clone, Debug)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    // todo: consider using pkcs11-uri here too
    pub fn try_from_der_file(filename: &String) -> Result<Self> {
        let der = fs::read(filename)?;
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

    pub fn public_key(&self) -> rsa::RSAPublicKey {
        let spki = self.certificate().tbs_certificate.subject_pki;
        assert_eq!(oid_registry::OID_PKCS1_RSAENCRYPTION, spki.algorithm.algorithm);
        rsa::RSAPublicKey::from_pkcs1(&spki.subject_public_key.data).unwrap()
    }

    pub fn fingerprint(&self) -> Sha256Hash {
        // no panic, DER is verified in constructor
        Sha256Hash(cert_fingerprint(self.certificate()).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct Certificates {
    certificate_ders: [Vec<u8>; 4],
}

impl Certificates {
    // todo: consider using pkcs11-uri here too
    pub fn try_from_der_files(certificate_der_filenames: &[String; 4]) -> Result<Self> {
        let mut ders = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for (der, filename) in ders.iter_mut().zip(certificate_der_filenames.iter()) {
            *der = fs::read(filename)?;
        }
        Certificates::try_from_ders(ders)
    }

    /// Checks certificates are valid, and public keys are all RSA.
    pub fn try_from_ders(certificate_ders: [Vec<u8>; 4]) -> Result<Self> {
        for der in certificate_ders.iter() {
            // implicitly checks public key is RSA
            let _ = cert_fingerprint(X509Certificate::from_der(der)?.1)?;
        }
        Ok(Self { certificate_ders })
    }

    pub fn certificate_0<'a>(&'a self) -> X509Certificate<'a> {
        self.certificate(0.into())
    }

    // the `i` parameter is a bit meh here
    pub fn certificate(&self, i: CertificateSlot) -> X509Certificate<'_> {
        // no panic, DER is verified in constructor
        X509Certificate::from_der(&self.certificate_ders[usize::from(i)]).unwrap().1
    }

    // the `i` parameter is a bit meh here
    pub fn certificate_der(&self, i: CertificateSlot) -> &[u8] {
        &self.certificate_ders[usize::from(i)]
    }

    pub fn fingerprints(&self) -> [Sha256Hash; 4] {
        let mut fingerprints = [Sha256Hash::default(); 4];
        for i in 0..4 {
            // no panic, DER is verified in constructor
            fingerprints[i] = Sha256Hash(cert_fingerprint(self.certificate(i.into())).unwrap());
        }
        fingerprints
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


pub struct SignedImage(Vec<u8>);

/// Technically probably incorrect naming, as no ownership of RoT keys is asserted.
pub struct ImageSigningRequest {
    pub plain_image: Vec<u8>,
    certificates: Certificates,
    pub slot: CertificateSlot,
}

impl ImageSigningRequest {

    pub fn from(plain_image: Vec<u8>, certificates: Certificates, slot: CertificateSlot) -> Self {
        Self { plain_image, certificates, slot }
    }

    /// Parse config, load all data checking for validity.
    pub fn try_from(config: &Config) -> Result<Self> {

        let plain_image = fs::read(&config.image)?;

        let certificates = Certificates::try_from_der_files(&config.root_cert_filenames)?;


        Ok(Self {
            plain_image,
            certificates,
            slot: config.root_cert_slot,
        })
    }

    pub fn certificates(&self) -> &Certificates {
        &self.certificates
    }

    /// TODO: pick CertificateSlot based on public keys
    pub fn sign(&self, signing_key: &SigningKey) -> SignedImage {
        let mut image = self.assemble_unsigned_image(self.slot);

        // signature
        let signature = signing_key.sign(&image);
        image.extend_from_slice(signature.as_ref());
        SignedImage(image)
    }

    fn assemble_unsigned_image(&self, i: CertificateSlot) -> Vec<u8> {

        let mut image = word_padded(&self.plain_image);

        let certificate = word_padded(self.certificates.certificate_der(i.into()));

        let total_image_size = modify_header(&mut image, certificate.len());
        println!("{:x}", total_image_size);

        let build_number = 1;
        let certificate_block_header = certificate_block_header_bytes(
            // total image size sans signature
            total_image_size - 256,
            certificate.len(),
            build_number,
        );
        // certificate block header
        image.extend_from_slice(&certificate_block_header);

        // certificate block
        extendu(&mut image, certificate.len());
        image.extend_from_slice(&certificate);

        // ROT key hash table
        for i in 0..4 {
            let fingerprint = cert_fingerprint(self.certificates.certificate(i.into())).unwrap();
            image.extend_from_slice(&fingerprint);
        }

        image

    }

}

/// Assembles a "signed image" and signs it.
///
/// Note that this is *not* an SB2.1 container image.
pub fn sign(config: &Config) -> Result<Vec<u8>> {
    let plain_image = fs::read(&config.image)?;
    let der = fs::read(&config.root_cert_filenames[0])?;

    let key = SigningKey::try_from_uri(config.root_cert_secret_key.as_ref())?;

    let rot_fingerprints = crate::rot_fingerprints::rot_fingerprints(&config.root_cert_filenames)?;
    let signed_image = assemble_signed_image(
        &plain_image,
        &der,
        rot_fingerprints,
        &key,
    );
    fs::write(&config.signed_image, &signed_image)?;
    Ok(signed_image)
}


fn assemble_signed_image(plain_image: &[u8], certificate_der: &[u8], rot_key_hashes: [[u8; 32]; 4], signing_key: &SigningKey) -> Vec<u8> {

    let mut image = word_padded(plain_image);
    let certificate = word_padded(certificate_der);

    let total_image_size = modify_header(&mut image, certificate.len());
    println!("{:x}", total_image_size);

    let build_number = 1;
    let certificate_block_header = certificate_block_header_bytes(
        // total image size sans signature
        total_image_size - 256,
        certificate.len(),
        build_number,
    );
    // certificate block header
    image.extend_from_slice(&certificate_block_header);

    // certificate block
    extendu(&mut image, certificate.len());
    image.extend_from_slice(&certificate);

    // ROT key hash table
    for rot_key_hash in rot_key_hashes.iter() {
        image.extend_from_slice(rot_key_hash.as_ref());
    }
    // signature
    let signature = signing_key.sign(&image);
    image.extend_from_slice(signature.as_ref());

    image

}

// UM11126, Chap. 6, Table 172, "Image header"
fn modify_header(padded_image: &mut Vec<u8>, padded_certificate_length: usize) -> usize {
    let image_size = padded_image.len();

    let non_image_size =
        // certificate block header
        32 +
        // certificate table size (each is u32(certificate size) + certificate, we have only one)
        (4 + padded_certificate_length) +
        // 4x ROT key SHA256 hash
        4*32 +
        // RSA2K signature
        256;

    let total_image_size = image_size + non_image_size;

    // 0x20: total image size
    padded_image[0x20..][..4].copy_from_slice((total_image_size as u32).to_le_bytes().as_ref());
    // 0x24: image type "SPT" = [XIP Signed, TZ disabled, 0, 0-]
    // This doesn't seem to match UM 11126, Chap. 7, Table 183 at all :)
    padded_image[0x24..][..4].copy_from_slice(&[0x04, 0x40, 0x00, 0x00]);
    // "header offset", i.e. image size
    padded_image[0x28..][..4].copy_from_slice((image_size as u32).to_le_bytes().as_ref());

    total_image_size
}

fn certificate_block_header_bytes(total_image_length: usize, aligned_cert_length: usize, build_number: u32) -> Vec<u8> {
    let mut bytes = Vec::new();

    // UM 11126, Chap 7, Table 185

    // actual header: first 16/32 bytes
    bytes.extend_from_slice(b"cert");
    // headerMajorVersion = 1
    extend16(&mut bytes, 1);
    // headerMinorVersion = 0
    extend16(&mut bytes, 0);
    // header length = 0x20
    extend32(&mut bytes, 0x20);
    // RFU
    extend32(&mut bytes, 0);

    // actual header: second 16/32 bytes
    // "for downgrade protection"
    // grep for FOUR_CHAR_CODE
    extend32(&mut bytes, build_number);
    extendu(&mut bytes, total_image_length);
    print!("set length to {:x}", total_image_length);

    let certificates: u32 = 1;
    // one certificate
    extend32(&mut bytes, certificates);
    // 0x480 = 1152
    extendu(&mut bytes, aligned_cert_length + 4);

    assert_eq!(32, bytes.len());

    bytes
}

fn extend16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(value.to_le_bytes().as_ref());
}

fn extend32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(value.to_le_bytes().as_ref());
}

#[allow(dead_code)]
fn extend64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(value.to_le_bytes().as_ref());
}

fn extendu(bytes: &mut Vec<u8>, value: usize) {
    // on desktop, usize is u64
    bytes.extend_from_slice((value as u32).to_le_bytes().as_ref());
}

