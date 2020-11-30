use std::fs;

use serde::{Deserialize, Serialize};

use crate::error::Result;


const IMAGE_ALIGNMENT: usize = 4;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub root_cert_secret_key: String,
    pub root_cert_filenames: [String; 4],
    pub image: String,
    pub signed_image: String,
    // pub factory: FactoryArea,
    // pub field: FieldAreaPage,
    // pub keystore: Keystore,
}

pub fn sign(config_filename: &str) -> Result<Vec<u8>> {
    let config = fs::read_to_string(config_filename)?;
    let mut config: Config = toml::from_str(&config)?;
    let plain_image = fs::read(config.image)?;
    let der = fs::read(&config.root_cert_filenames[0])?;

    let sk_data = fs::read_to_string(&config.root_cert_secret_key)?;
    // do this instead:
    // https://docs.rs/rsa/0.3.0/rsa/struct.RSAPrivateKey.html?search=#example
    let der_bytes = pem_parser::pem_to_der(&sk_data);
    // use std::io::BufRead;
    // let der_encoded = sk_data
    //     .lines()
    //     .filter(|line| !line.starts_with("-"))
    //     .fold(String::new(), |mut data, line| {
    //         data.push_str(&line);
    //         data
    //     });
    // let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");
    let sk = rsa::RSAPrivateKey::from_pkcs1(&der_bytes)?;

    let rotkh = crate::rotkh::rot_key_hashes(&config.root_cert_filenames)?;
    let signed_image = assemble_signed_image(
        &plain_image,
        &der,
        rotkh,
        &sk,
    );
    fs::write(&config.signed_image, &signed_image)?;
    Ok(signed_image)
}


fn pad_alignment(data: &mut Vec<u8>) {
    let size = data.len();
    let padding = if (size % IMAGE_ALIGNMENT) > 0 {
        IMAGE_ALIGNMENT - (size % IMAGE_ALIGNMENT)
    } else {
        0
    };
    let aligned_size = size + padding;
    data.resize(aligned_size, 0);
}

fn padded_alignment(data: &[u8]) -> Vec<u8> {
    let mut data = Vec::from(data);
    pad_alignment(&mut data);
    data
}

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
    padded_image[0x24..][..4].copy_from_slice(&[0x04, 0x40, 0x00, 0x00]);
    // "header offset", i.e. image size
    padded_image[0x28..][..4].copy_from_slice((image_size as u32).to_le_bytes().as_ref());

    total_image_size
}

pub struct CertificateBlockHeader {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
}

fn extend16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(value.to_le_bytes().as_ref());
}

fn extend32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(value.to_le_bytes().as_ref());
}

fn extend(bytes: &mut Vec<u8>, value: usize) {
    // on desktop, usize is u64
    bytes.extend_from_slice((value as u32).to_le_bytes().as_ref());
}

fn certificate_block_header_bytes(total_image_length: usize, aligned_cert_length: usize, build_number: u32) -> Vec<u8> {
    let mut bytes = Vec::new();

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
    extend(&mut bytes, total_image_length);
    print!("set length to {:x}", total_image_length);

    let certificates: u32 = 1;
    // one certificate
    extend32(&mut bytes, 1);
    // 0x480 = 1152
    extend(&mut bytes, aligned_cert_length + 4);

    assert_eq!(32, bytes.len());

    bytes
}

fn assemble_signed_image(plain_image: &[u8], certificate_der: &[u8], rot_key_hashes: [[u8; 32]; 4], secret_key: &rsa::RSAPrivateKey) -> Vec<u8> {

    let mut image = padded_alignment(plain_image);
    let certificate = padded_alignment(certificate_der);

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
    extend(&mut image, certificate.len());
    image.extend_from_slice(&certificate);

    // ROT key hash table
    for rot_key_hash in rot_key_hashes.iter() {
        image.extend_from_slice(rot_key_hash.as_ref());
    }
    // signature
    let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&image);
    let hashed_image = hasher.finalize();
    let signature = secret_key.sign(padding_scheme, &hashed_image).expect("signatures work");
    assert_eq!(256, signature.len());
    image.extend_from_slice(&signature);

    image

}

//fn assemble_sb_file(bin: Vec<u8>) -> Vec<u8> {
//    // AN12283, section 2.3 "Signed image"
//    // First comes a header: elftosb/common/AuthImageGenerator.h:200-210 (es_header_t)
//    // - 0x0 ??
//    // - 0x20 image length                <-- this and following set in elftosb/common/AuthImageGenerator.cpp:1204
//    // - 0x24 image type: "SPT"
//    // - 0x28 header offset
//    // - ??
//    // - 0x34 load address
//    // - plain image (assume this means .bin?)
//    // - certificate block header
//    // - X.509 certificate
//    // - RoT key 0 hash
//    // - RoT key 1 hash
//    // - RoT key 2 hash
//    // - RoT key 3 hash
//    // - data (TrustZone config)
//    // - RSASSA-PKCS1-v1_5 signature
//    //

//    // Instructions:
//    // - load .bin file, pad to 4 bytes with zeros (-> image_size)
//    // - patch in 0x20 (image_size, u32-le), 0x24 ('04 40 00 00' = '<signed> <no-TZ> 00 00'), 0x28
//    // = uhhh.. double check the two numbers at 0x20 and 0x28
//    // - save padded+modified .bin file
//    // - add certificate header block:
//    //   'cert'    01      02     00
//    //   build  imglen certs=1  certslen = 4 + padded DER cert len
//    // - add cert, prefixed by its length (u32-le), padded with zeros to 4-byte alignment
//    // - add 4x ROT SHA2 (32B each)
//    // - add 256B RSASSA PKCS v1.5 signature

//    let length = bin.len();
//    assert!(length % 8 == 0);
//    modify_header(&mut bin);
//}
