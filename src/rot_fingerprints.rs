//! NXP's approach to public key fingerprints (aka ROTKH)
//!
//! For each RSA public key PK with modulus `n` and exponent `e`,
//! the fingerprint is defined as
//! ```ignore
//! fp(PK) = SHA256(n.to_be_bytes() | e.to_be_bytes())
//! ```
//!
//! For a bundle of four "root certificates" `PK1`, `PK2`, `PK3`, `PK4`, the fingerprint is defined as
//! ```ignore
//! fp(bundle) = SHA256(fp(PK1) | fp(PK2) | fp(PK3) | fp(PK4))
//! ```

use anyhow::Result;
use crate::protected_flash::{CustomerSettings, Keystore, FactorySettings, Sha256Hash};

use core::convert::TryInto;
use std::fs;

use rsa::PublicKeyParts as _;
use sha2::Digest as _;
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;

// #[derive(Clone, Debug, Deserialize, Serialize)]
// pub struct CfpaConfig {
//     pub rot_keys_status: RotKeysStatus,
//     pub boot_configuration: BootConfiguration,
//     pub usb_vid_pid: UsbVidPid,
// }

// #[derive(Clone, Debug, Deserialize, Serialize)]
// pub struct CmpaConfig {
//     pub secure_boot_configuration: SecureBootConfiguration,
// }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub root_cert_filenames: [String; 4],
    pub factory: FactorySettings,
    pub customer: CustomerSettings,
    pub keystore: Keystore,
}

/// NXP-specific construction that gives a fingerprint of an RSA public key
///
/// It's SHA256(big endian modulus || big endian exponent)
///
/// This is an RSA thing, public keys are ~256B (RSA2048), while the hash is "only" 32B
pub fn key_fingerprint(public_key: rsa::RSAPublicKey) -> [u8; 32] {
    let n = public_key.n();
    let e = public_key.e();
    // e.g., n = 21180609610011908974245154634009773742409228475924832420640732487602371552607208434815604239733761061624595772266076892772797402260546921881940097799828803122149358818132191889899441450923166919457193292916001584543268399036684342230632304039418343776750540042195439119799724089028829483927297432554313701904867373619640752457487405782173272827509578742485272792121363761115153135595006648746766049001063218844454972346390444289285459567420247245376227517357296502996294373645061373559719690903237831034883266667892726893796797389886027843919406367649873994790265470728806388647429250289865772615066974316813540762961
    trace!("n = {}, e = {}", n, e);
    debug!("n bytes = \"{}\"", hex_str!(&n.to_bytes_be(), 4));

    let mut hasher = sha2::Sha256::new();
    hasher.update(n.to_bytes_be());
    hasher.update(e.to_bytes_be());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// NXP-specific construction that gives a "fingerprint" of the certificate's public key,
/// assuming said key is RSA
pub fn cert_fingerprint(certificate: X509Certificate<'_>) -> Result<[u8; 32]> {
    let spki = certificate.tbs_certificate.subject_pki;
    trace!("alg: {:?}", spki.algorithm.algorithm);
    // let OID_RSA_ENCRYPTION = oid!(1.2.840.113549.1.1.1);
    assert_eq!(oid_registry::OID_PKCS1_RSAENCRYPTION, spki.algorithm.algorithm);

    let public_key = rsa::RSAPublicKey::from_pkcs1(&spki.subject_public_key.data)?;
    Ok(key_fingerprint(public_key))
}

pub fn rot_fingerprints(certs: &[String; 4]) -> Result<[[u8; 32]; 4]> {
    let mut hashes = [[0u8; 32]; 4];
    for (i, cert_filename) in certs.iter().enumerate() {
        let cert_content = fs::read(cert_filename)?;
        let (rem, cert) = x509_parser::parse_x509_certificate(&cert_content)?;
        assert!(rem.is_empty());

        hashes[i] = cert_fingerprint(cert)?;
    }
    Ok(hashes)
}

pub fn calculate(config_filename: &str) -> Result<()> {
    let config = fs::read_to_string(config_filename)?;
    let mut config: Config = toml::from_str(&config)?;
    // config.factory.prince_subregions[2] = crate::pfr::PrinceSubregion::from_bits_truncate(0x55);
    // debug!("loaded config:\n\n{}", serde_yaml::to_string(&config)?);
    // debug!("loaded config:\n\n{}", toml::to_string(&config)?);
    // debug!("loaded config:\n\n{:?}", &config);

    let mut hash = sha2::Sha256::new();

    let fingerprints = rot_fingerprints(&config.root_cert_filenames)?;
    for fingerprint in fingerprints.iter() {
        hash.update(&fingerprint);
    }
    let rot_fingerprint = hash.finalize();

    config.factory.rot_fingerprint = Sha256Hash(rot_fingerprint.try_into().unwrap());
    info!("RoT fingerprint: {}", hex_str!(&rot_fingerprint, 4));

    debug!("loaded config: {}", serde_yaml::to_string(&config)?);
    debug!("rot_keys_status as u32: 0x{:x}", u32::from(config.customer.rot_keys_status));
    debug!("boot_configuration as u32: 0x{:x}", u32::from(config.factory.boot_configuration));
    debug!("secure_boot_configuration as u32: 0x{:x}", u32::from(config.factory.secure_boot_configuration));

    debug!("factory settings: {}", hex_str!(config.factory.to_bytes()?.as_ref(), 4));
    debug!("customer settings: {}", hex_str!(config.customer.to_bytes()?.as_ref(), 4));
    debug!("keystore: {}", hex_str!(config.keystore.to_bytes().as_ref(), 4));

    Ok(())
}
