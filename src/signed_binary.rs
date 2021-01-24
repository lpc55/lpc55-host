use core::convert::TryFrom;
use std::fs;

use anyhow::Result;

use crate::secure_binary::Config;
use crate::pki::{Certificate, Certificates, CertificateSlot, CertificateSource, SigningKey};
use crate::util::word_padded;

pub struct SignedImage(pub Vec<u8>);

/// Technically probably incorrect naming, as no ownership of RoT keys is asserted.
pub struct ImageSigningRequest {
    pub plain_image: Vec<u8>,
    certificates: Certificates,
    signing_key: SigningKey,
    pub slot: CertificateSlot,
}

impl ImageSigningRequest {

    // pub fn from(plain_image: Vec<u8>, certificates: Certificates, signing_key: SigningKey) -> Self {
    //     Self { plain_image, certificates, slot }
    // }

    /// Parse config, load all data checking for validity.
    pub fn try_from(config: &Config) -> Result<Self> {

        let plain_image = fs::read(&config.firmware.image)?;

        let certificate_sources = [
            CertificateSource::try_from(config.pki.certificates[0].as_ref())?,
            CertificateSource::try_from(config.pki.certificates[1].as_ref())?,
            CertificateSource::try_from(config.pki.certificates[2].as_ref())?,
            CertificateSource::try_from(config.pki.certificates[3].as_ref())?,
        ];
        let certificates = Certificates::try_from(&certificate_sources)?;

        let signing_key = SigningKey::try_from_uri(config.pki.signing_key.as_ref())?;

        let slot = certificates.index_of(signing_key.public_key())?;

        Ok(Self {
            plain_image,
            certificates,
            signing_key,
            slot: slot,
        })
    }

    pub fn selected_certificate(&self) -> &Certificate {
        self.certificates.certificate(self.slot)
    }

    pub fn certificates(&self) -> &Certificates {
        &self.certificates
    }

    /// Fails only if signing key does not match selected certificate slot
    pub fn sign(&self) -> SignedImage {
        // if signing_key.public_key() != self.selected_certificate().public_key() {
        //     return Err(anyhow::anyhow!("Signing key does not match selected certificate slot!"));
        // }
        let mut image = self.assemble_unsigned_image(self.slot);

        // signature
        let signature = self.signing_key.sign(&image);
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
            let fingerprint = self.certificates.certificate(i.into()).fingerprint();
            image.extend_from_slice(&fingerprint.0);
        }

        image
    }
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

