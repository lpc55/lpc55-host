use crate::error::Result;
use crate::types::to_hex_string;
use crate::pfr::{FieldAreaPage, Keystore, ManufacturerArea, Sha256Hash};

use core::convert::TryInto;
use std::fs;

use rsa::PublicKeyParts as _;
use sha2::Digest as _;
use serde::{Deserialize, Serialize};

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
    pub factory: ManufacturerArea,
    pub field: FieldAreaPage,
    pub keystore: Keystore,
}

pub fn calculate(config_filename: &str) -> Result<()> {
    let config = fs::read_to_string(config_filename)?;
    let mut config: Config = toml::from_str(&config)?;
    // config.factory.prince_subregions[2] = crate::pfr::PrinceSubregion::from_bits_truncate(0x55);
    // debug!("loaded config:\n\n{}", serde_yaml::to_string(&config)?);
    // debug!("loaded config:\n\n{}", toml::to_string(&config)?);
    // debug!("loaded config:\n\n{:?}", &config);

    let mut hash = sha2::Sha256::new();

    for cert_filename in config.root_cert_filenames.iter() {
        let cert_content = fs::read(cert_filename)?;
        let (rem, cert) = x509_parser::parse_x509_der(&cert_content)?;
        assert!(rem.is_empty());
        let spki = cert.tbs_certificate.subject_pki;
        trace!("alg: {:?}", spki.algorithm.algorithm);
        assert_eq!(x509_parser::objects::OID_RSA_ENCRYPTION, spki.algorithm.algorithm);

        let public_key = rsa::RSAPublicKey::from_pkcs1(&spki.subject_public_key.data)?;
        let n = public_key.n();
        let e = public_key.e();
        trace!("n = {}, e = {}", n, e);
        trace!("n bytes = {:?}", crate::types::to_hex_string(&n.to_bytes_be()));

        let mut hasher = sha2::Sha256::new();
        hasher.update(n.to_bytes_be());
        hasher.update(e.to_bytes_be());
        let result = hasher.finalize();

        hash.update(result);
    }

    let rotkh = hash.finalize();
    config.factory.rot_keys_table_hash = Sha256Hash(rotkh.try_into().unwrap());
    info!("rotkh = {}", to_hex_string(&rotkh));
    println!("{}", to_hex_string(&rotkh));

    debug!("loaded config: {}", serde_yaml::to_string(&config)?);
    debug!("rot_keys_status as u32: 0x{:x}", u32::from(config.field.rot_keys_status));
    debug!("boot_configuration as u32: 0x{:x}", u32::from(config.factory.boot_configuration));
    debug!("secure_boot_configuration as u32: 0x{:x}", u32::from(config.factory.secure_boot_configuration));

    debug!("factory: {}", to_hex_string(config.factory.to_bytes().as_ref()));
    debug!("field: {}", to_hex_string(config.field.to_bytes().as_ref()));
    debug!("keystore: {}", to_hex_string(config.keystore.to_bytes().as_ref()));

    Ok(())
}
