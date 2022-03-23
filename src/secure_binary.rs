//! Generator and parser for signed firmware and SB (secure binary) files
//!
//! The format is as follows:
//!
//! Sb21HeaderPart:
//! - Sb2Header (6 blocks, 96B)
//! - DigestHMAC (2 blocks, 32B = HMAC(boot tag HMAC | section HMAC))
//! - Keyblob (5 blocks, 80B)
//! - CertificateBlockHeader (2 blocks, 32B)
//! - Certificate length (4B)
//! - Certificate DER data (word-padded)
//! - ROT fingerprints (8 blocks, 4x32B = 128B)
//! - Signature (16 blocks, 256B = 2048 bits)
//!
//! Sb21CommandPart:
//! - encrypted boot tag (16B)
//! - boot tag HMAC (32B = HMAC(encrypted boot tag))
//! - section HMAC (32B = HMAC(encrypted command section))
//! - encrypted command section (variable, block padded)
//!
//! Key blob is the AES-keywrap (with SBKEK) of a 32B "data encryption key" (DEK)
//! and a 32B "message authentication key" (MAC). Keywrap adds an 8B tag, which is
//! further block padded with 8 zeros to 80B.
//!
//! The RSA2k signature is over all that precedes it, in particular the HMAC of the
//! HMACs of the command part.

#![allow(unused_imports)]

use std::convert::{TryFrom, TryInto};
use std::fs;

use anyhow::{Context as _, Result};
pub use chrono::naive::NaiveDate;
use rsa::pkcs1::FromRsaPublicKey;
use serde::{Deserialize, Serialize};
use x509_parser::{certificate::X509Certificate, traits::FromDer};

use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_while_m_n},
    combinator::{map, value, verify},
    multi::fill,
    number::complete::{be_u16, be_u32, le_u128, le_u16, le_u32, le_u64, u8},
    sequence::tuple,
};

use crate::crypto::{crc32, hmac, nxp_aes_ctr_cipher, sha256};
use crate::pki::{CertificateSlot, Certificates, Pki, Sha256Hash, SigningKey, SigningKeySource};
use crate::protected_flash::{CustomerSettings, FactorySettings};
use crate::util::{
    hex_deserialize_256, hex_deserialize_32, hex_serialize, is_default, word_padded,
};
use signature::Signature as _;

pub mod command;

use command::{
    BootCommand, BootCommandDescription, BootCommandSequenceDescription,
    SingleBootCommandDescription,
};

/// Main configuration file format for chip configuration and secure/signed firmware
/// image/container generation.
///
/// TODOs:
/// - check if `factory-settings.rot-fingerprint` matches `pki.certificates`' fingerprint
/// - ...
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub firmware: Firmware,
    pub pki: Pki,

    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub reproducibility: Reproducibility,

    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub factory_settings: FactorySettings,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub customer_settings: CustomerSettings,

    /// Commands and command sequences for the SB file
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub commands: Vec<BootCommandDescription>,
}

impl TryFrom<&'_ str> for Config {
    type Error = anyhow::Error;
    fn try_from(config_filename: &str) -> anyhow::Result<Self> {
        let config = fs::read_to_string(config_filename)
            .with_context(|| format!("Failed to read config from {}", config_filename))?;
        let config: Config = toml::from_str(&config)?;
        trace!("{:#?}", &config);
        Ok(config)
    }
}

/// Firmware versions and image locations.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Firmware {
    /// Path to the input image (can be ~~ELF,~~ signed or unsigned BIN)
    pub image: String,

    /// Path to place signed binary
    pub signed_image: String,

    /// Path to place signed SB2.1 file
    pub secure_boot_image: String,
    // pub factory: FactorySettings,
    // pub customer: CustomerSettings,
    // pub keystore: Keystore,
    //
    pub build: u32,
    pub component: Version,
    pub product: Version,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Reproducibility {
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    #[serde(deserialize_with = "hex_deserialize_256")]
    #[serde(default)]
    /// Encryption key for SB2.1 command sections.
    ///
    /// If left out, `[0u8; 32]` is used.
    pub dek: [u8; 32],
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    #[serde(deserialize_with = "hex_deserialize_256")]
    #[serde(default)]
    /// MAC key for SB2.1 command sections.
    ///
    /// If left out, `[0u8; 32]` is used.
    pub mac: [u8; 32],
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    /// Nonce for the "AES-CTR-in-NXP-variant" encryption of the firmware.
    ///
    /// If left out, all zeros are used.
    ///
    /// This differs from vendor's `elftosb`, in order to ensure default
    /// reproducibility, and we don't have the encrypted firmware use case.
    pub nonce: [u32; 4],
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    /// Timestamp in microseconds since 2000-01-01
    ///
    /// If left out of configuration, when signing the `product` version
    /// of `Firmware` is is interpreted as calver (i.e., minor version is
    /// interpreted as days since 2020-01-01) and used. This is in contrast
    /// to the vendor's implementation, which uses "current" time, making the
    /// build unreproducible.
    pub timestamp: u64,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    #[serde(serialize_with = "hex_serialize")]
    #[serde(deserialize_with = "hex_deserialize_32")]
    /// NXP fills the last 4 bytes of `Sb2Header` with random values.
    ///
    /// For the non-private firmware case (where encryption is a farce, since SBKEK is well-known),
    /// if this is left out, we use `[0u8; 4]`. The configuration option exists to match `elftosb`
    /// generated SB2.1 containers with ours (by copying their choice).
    pub sb_header_padding: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Filetype {
    Elf,
    UnsignedBin,
    SignedBin,
    Sb20,
    Sb21,
}

pub fn sniff(file: &[u8]) -> Result<Filetype> {
    Ok(match &file[..4] {
        // ELF
        b"\x7fELF" => Filetype::Elf,
        // BIN
        // this criterion is a bit unstable I guess.
        // https://interrupt.memfault.com/blog/zero-to-main-1
        // firmware starts with SP (4b) then PC (4B)
        // maybe: fallback to viewing as "bin" if not ELF or SB?
        &[0x00, 0x00, 0x04, 0x20] => match file[0x20..0x24] {
            [0x00, 0x00, 0x00, 0x00] => Filetype::UnsignedBin,
            _ => Filetype::SignedBin,
        },
        _ => {
            match &file[20..24] {
                // SB2.0 or SB2.1
                b"STMP" => match &file[52..56] {
                    b"sgtl" => Filetype::Sb21,
                    _ => Filetype::Sb20,
                },
                // out of ideas
                _ => {
                    return Err(anyhow::anyhow!("no clue"));
                }
            }
        }
    })
}

#[derive(Clone, Debug)]
pub struct Sb21FileParameters {
    // figure out once and for all what this really is represented as best..
    nonce: [u32; 4],
    // the "default" here (cf. eg.
    // https://github.com/NXPmicro/spsdk/blob/master/spsdk/sbfile/headers.py#L65)
    // is 0x08 which means "Signed" image (and they even `else "Unsigned"`
    // flags: u16,
    /// millisec since 2000-01-01
    timestamp: u64,
    product: Version,
    component: Version,
    build: u32,
    sb_header_padding: [u8; 4],
}

#[derive(Clone, Debug)]
pub struct UnsignedSb21File {
    // header stuff
    pub parameters: Sb21FileParameters,

    // would like to have the decoded certificates here,
    // but they're always "views". Maybe create our own X509Certificate struct,
    // which owns the DER-encoded cert as Vec<u8>, and returns parsed view on demand.
    // certificates: [X509Certificate<'static>; 4],
    pub certificates: Certificates,
    pub slot: CertificateSlot,
    pub keyblob: Keyblob,
    pub commands: Vec<BootCommand>,
}

#[derive(Clone, Debug)]
pub struct Sb21CommandPart {
    encrypted_boot_tag: [u8; 16],
    unencrypted_hmac_of_encrypted_boot_tag: [u8; 32],
    unencrypted_hmac_of_encrypted_section: [u8; 32],
    encrypted_section: Vec<u8>,
}

impl Sb21CommandPart {
    // probably don't need this
    fn hmac_table(&self) -> [[u8; 32]; 2] {
        [
            self.unencrypted_hmac_of_encrypted_boot_tag,
            self.unencrypted_hmac_of_encrypted_section,
        ]
    }

    fn digest_hmac(&self, mac_key: [u8; 32]) -> [u8; 32] {
        let mut raw_table = Vec::new();
        let hmac_table = self.hmac_table();
        raw_table.extend_from_slice(&hmac_table[0]);
        raw_table.extend_from_slice(&hmac_table[1]);
        hmac(mac_key, &raw_table)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::from(self.encrypted_boot_tag.as_ref());
        bytes.extend_from_slice(&self.unencrypted_hmac_of_encrypted_boot_tag);
        bytes.extend_from_slice(&self.unencrypted_hmac_of_encrypted_section);
        bytes.extend_from_slice(&self.encrypted_section);
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct SignedSb21File {
    pub unsigned_file: UnsignedSb21File,
    pub header_part: Sb21HeaderPart,
    pub command_part: Sb21CommandPart,
    pub signature: Vec<u8>,
}

impl Sb21HeaderPart {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut cert_block = Vec::new();
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.encrypted_keyblob);
        cert_block.extend_from_slice(&self.certificate_block_header.to_bytes());
        cert_block.extend_from_slice(&(self.padded_certificate0_der.len() as u32).to_le_bytes());
        assert!(self.padded_certificate0_der.len() > 100);
        cert_block.extend_from_slice(&self.padded_certificate0_der);
        for fp in self.rot_fingerprints.iter() {
            cert_block.extend_from_slice(fp.0.as_ref());
        }
        // Pad 16
        cert_block.resize(((cert_block.len() + 15) / 16) * 16, 0);

        bytes.extend_from_slice(&cert_block);

        bytes
    }
}

#[derive(Clone, Debug)]
pub struct Sb21HeaderPart {
    header: Sb2Header,
    digest: [u8; 32],
    // not sure if the 8 bytes padding can be set to zero or not
    encrypted_keyblob: [u8; 80],
    certificate_block_header: FullCertificateBlockHeader,
    #[allow(dead_code)]
    unpadded_cert_length: usize,
    padded_certificate0_der: Vec<u8>,
    rot_fingerprints: [Sha256Hash; 4],
}

impl UnsignedSb21File {
    pub fn try_assemble_from(config: &Config) -> anyhow::Result<Self> {
        // // would like to have the decoded certificates here,
        // // but they're always "views". Maybe create our own X509Certificate struct,
        // // which owns the DER-encoded cert as Vec<u8>, and returns parsed view on demand.
        // // certificates: [X509Certificate<'static>; 4],
        // pub certificates: Certificates,
        // pub keyblob: Keyblob,
        // pub commands: Vec<BootCommand>,

        let parameters = Sb21FileParameters {
            nonce: config.reproducibility.nonce,
            // nonce: {
            //     match config.reproducibility.nonce {
            //         [0, 0, 0, 0] => rand::random(),
            //         nonce => nonce,
            //     }
            // },
            timestamp: match config.reproducibility.timestamp {
                0 => config.firmware.product.timestamp_micros(),
                timestamp => timestamp,
            },
            build: config.firmware.build,
            component: config.firmware.component,
            product: config.firmware.product,
            sb_header_padding: config.reproducibility.sb_header_padding,
        };

        let certificates = Certificates::try_from_pki(&config.pki)?;
        let signing_key = SigningKey::try_from_uri(config.pki.signing_key.as_ref())?;
        let slot = certificates.index_of(signing_key.public_key())?;

        let keyblob = Keyblob {
            dek: config.reproducibility.dek,
            mac: config.reproducibility.mac,
        };

        let mut commands: Vec<BootCommand> = Vec::new();
        for command_or_sequence in config.commands.iter() {
            match command_or_sequence {
                BootCommandDescription::Single(command) => commands.push(command.try_into()?),

                BootCommandDescription::Sequence(sequence) => {
                    match sequence {
                        BootCommandSequenceDescription::UploadSignedImage => {
                            let mut image =
                                fs::read(&config.firmware.signed_image).with_context(|| {
                                    format!(
                                        "Failed to read signed firmware image from {}",
                                        config.firmware.signed_image
                                    )
                                })?;
                            let unpadded_image_size = image.len();

                            // Pad size to make 512 aligned
                            let block_overshoot = unpadded_image_size % 512;
                            if block_overshoot != 0 {
                                let padding = 512 - block_overshoot;
                                image.resize(unpadded_image_size + padding, 0);
                            }

                            let (first_block, remainder) = image.split_at(512);

                            info!("Adding: EraseRegion {}, {}", 0, image.len());
                            commands.push(BootCommand::EraseRegion {
                                address: 0,
                                bytes: image.len() as u32,
                            });

                            if !remainder.is_empty() {
                                // Skip first 512 bytes to protect from power loss
                                info!("Adding: Load {}, {} bytes", 512, remainder.len());
                                commands.push(BootCommand::Load {
                                    address: 512,
                                    data: Vec::from(remainder),
                                });
                            }

                            // Write the 512 bytes that we skipped, last.
                            info!("Adding: Load {}, {} bytes", 0, 512);
                            commands.push(BootCommand::Load {
                                address: 0,
                                data: Vec::from(first_block),
                            });
                        }
                        BootCommandSequenceDescription::CheckDerivedFirmwareVersions => {
                            let version = config.firmware.product;
                            if version.major >= 1024 || version.minor > 9999 || version.patch >= 64
                            {
                                return Err(anyhow::anyhow!(
                                    "config.firmware.product can at most be 1023.9999.63 for CheckDerivedFirmwareVersions"));
                            }
                            let version_to_check: u32 = ((version.major as u32) << 22)
                                | ((version.minor as u32) << 6)
                                | version.patch as u32;

                            info!(
                                "Checking firmware versions against: {:08x}",
                                version_to_check
                            );

                            commands.push(BootCommand::CheckSecureFirmwareVersion {
                                version: version_to_check,
                            });

                            commands.push(BootCommand::CheckNonsecureFirmwareVersion {
                                version: version_to_check,
                            });
                        }
                    }
                }
            }
        }

        let return_value = Self {
            parameters,
            certificates,
            slot,
            keyblob,
            commands,
        };
        // dbg!(return_value.clone());
        // panic!();
        Ok(return_value)
    }

    // let (i, header) = Sb2Header::inner_from_bytes(&data)?;//.unwrap();//.1;//.map_err(|_| anyhow::anyhow!("could not parse SB2 file"))?.1;
    // let (i, digest_hmac) = take::<_, _, ()>(32u8)(i)?;
    // let (i, keyblob) = Keyblob::from_bytes(i)?;
    // let (i, certificate_block_header) = FullCertificateBlockHeader::from_bytes(i)?;
    // let (i, certificate_length) = le_u32::<_, ()>(i).unwrap();
    // let (i, certificate_data) = take::<_, _, ()>(certificate_length)(i)?;
    // let (i, _rot_key_hashes) = take::<_, _, ()>(128usize)(i)?;
    // let (i, signature) = take::<_, _, ()>(256usize)(i)?;
    pub fn header_part(&self) -> Sb21HeaderPart {
        // todo: should we mark this method as unsafe and pass command part
        // as another parameter "for efficiency"?
        let digest = self.command_part().digest_hmac(self.keyblob.mac);

        let encrypted_keyblob = self.keyblob.to_bytes();

        let mut padded_certificate0_der = Vec::from(self.certificates.certificate_der(self.slot));
        let unpadded_cert_length = padded_certificate0_der.len();
        // let padded_len = 16*((unpadded_cert_length + 15)/16);
        let padded_len = 4 * ((unpadded_cert_length + 3) / 4);
        // dbg!(padded_certificate0_der.len());
        padded_certificate0_der.resize(padded_len, 0);
        // dbg!(padded_certificate0_der.len());
        // panic!();

        // really?
        // let cert_table_len = 4 + padded_certificate0_der.len() as u32 + 4;
        let cert_table_len = 4 + padded_certificate0_der.len() as u32;
        // really?
        // let total_image_length_in_bytes = self.signed_data_length() as _;
        let total_image_length_in_bytes = (((cert_table_len + 368) + 15) / 16) * 16;
        let certificate_block_header = FullCertificateBlockHeader {
            header_length_in_bytes: 32,
            build_number: self.parameters.build,
            total_image_length_in_bytes,
            certificate_count: 1,
            certificate_table_length_in_bytes: cert_table_len,
        };

        let rot_fingerprints = self.certificates.fingerprints();

        let header = Sb2Header {
            nonce: self.parameters.nonce,
            // the 1 in SB2.1
            header_version_minor: 1,
            // "signed" image
            flags: 0x08,
            // this needs to be everything-everything ( i.e., len(file.sb2)/16 )
            image_size_blocks: self.total_serialized_length() as u32 / 16,
            boot_tag_offset_blocks: self.boot_tag_offset_blocks() as u32,

            // 6 entries that seem only here to "fit in" the general SB scheme
            boot_section_id: 0,
            // 16 * ( header(6) + digest(2) + keyblob(5))
            certificate_block_header_offset_bytes: 16 * 13,
            // "fact of life"
            header_size_blocks: 6,
            // header (6) + digest (2)
            keyblob_offset_blocks: 8,
            keyblob_size_blocks: 5,
            max_section_mac_count: 1,
            // end of "the 6 entries"
            timestamp_microseconds_since_millenium: self.parameters.timestamp,
            product_version: self.parameters.product,
            component_version: self.parameters.component,
            build_number: self.parameters.build,
            sb_header_padding: self.parameters.sb_header_padding,
        };
        Sb21HeaderPart {
            header,
            digest,
            encrypted_keyblob,
            certificate_block_header,
            unpadded_cert_length,
            padded_certificate0_der,
            rot_fingerprints,
        }
    }

    pub fn total_serialized_length(&self) -> usize {
        // this needs to be everything-everything (i.e., len(file.sb2))
        let blocks = self.boot_tag_offset_blocks()
            // boot tag(1) + hmac table(2*2)
            + 5
            // the actual payload
            + self.command_part().encrypted_section.len()/16;

        blocks * 16
    }

    pub fn signed_data_length(&self) -> usize {
        // need "padded" length here
        let certificate_length = 4 * ((self.certificates.certificate_der(self.slot).len() + 3) / 4);

        // let header_blocks = 16;
        // let keyblob_blocks = 5;
        let signed_data_length = 16 * (6 + 2 + 5 + 2) + 4 + certificate_length + 128;

        // pad 16
        16 * ((signed_data_length + 15) / 16)
    }

    pub fn boot_tag_offset_blocks(&self) -> usize {
        // entire header section is "data to be signed" + signature
        // a block is 16 bytes
        (self.signed_data_length() + 256) / 16
    }

    // alright, BootTag, Hmac, Section
    //
    // here's what happens:
    // - encryption is weird... (big-endian AES-CTR, but with nonce modified by adding
    // block number to little-endian encoding of last nonce-value)
    //
    // - first: encrypted boot tag
    // - then: unencrypted HMAC of encrypted boot tag
    // - then: unencrypted HMAC of encrypted section data (commands and their data)
    // - then: encrypted section data
    //
    // the digest HMAC at the top after image header is HMAC(first HMAC || second HMAC)

    // TODO: since everything is private (?) and we only use shared references,
    // should be possible to cache this part. Alternatively, inject a "with rendered command part"
    // typestate between unsigned and signed image (we need the hmacs, and the length)
    pub fn command_part(&self) -> Sb21CommandPart {
        let mut section = Vec::new();
        for command in self.commands.iter() {
            section.append(&mut command.to_bytes());
        }
        let encrypted_section = nxp_aes_ctr_cipher(
            &section,
            self.keyblob.dek,
            self.parameters.nonce,
            // 1 block bot tag, 2 blocks each per HMAC
            self.boot_tag_offset_blocks() as u32 + 5,
        );

        // let expected_load_command = nxp_aes_ctr_cipher(
        //     &hex::decode("482942772afd7a89c880de80c2553ce8").unwrap(),
        //     self.keyblob.dek,
        //     self.parameters.nonce,
        //     self.boot_tag_offset_blocks() as u32 + 6,
        // );
        // 54020000 00000000 78090000 7E976AF8
        // println!("expected load command: {}", hex_str!(&expected_load_command, 4));
        // 03020000 00000000 78090000 FD96E7AC (...)
        // println!("actual load command: {}", hex_str!(&self.commands[1].to_bytes(), 4));
        // panic!();

        // let expected_encrypted = hex::decode("F24D0184C7177577157ECFACD1F7C24B").unwrap();
        // let expected_decrypted = nxp_aes_ctr_cipher(
        //     &expected_encrypted,
        //     self.keyblob.dek,
        //     self.parameters.nonce,
        //     self.boot_tag_offset_blocks() as u32,
        // );
        // expected: DE010180 00000000 01000000 01000000
        // println!("expected: {}", hex_str!(&expected_decrypted, 4));

        // // let expected_encrypted = hex::decode("F24D0184C7177577157ECFACD1F7C24B").unwrap();
        // let expected_encrypted = hex::decode("F05E23DC886A4418F41996FD7E20F1E1").unwrap();
        // let expected_decrypted = nxp_aes_ctr_cipher(
        //     &expected_encrypted,
        //     self.keyblob.dek,
        //     self.parameters.nonce,
        //     self.boot_tag_offset_blocks() as u32,
        // );
        // // expected: DE010180 00000000 01000000 01000000
        // println!("expected: {}", hex_str!(&expected_decrypted, 4));

        let last = self.commands.is_empty();
        // TODO: figure out tag and flags here
        let tag = 0x0;
        // https://github.com/NXPmicro/spsdk/blob/90fdc7e60917bdd01c0d1467bff7931551fe80f3/spsdk/sbfile/sb1/headers.py#L22
        // bit 0 = bootable (is set)
        // bit 1 = cleartext (is not set)
        // 0b01 = not cleartext bit 1 = "bootable", bit
        let flags = 0x1;
        let cipher_blocks = encrypted_section.len() as u32 / 16;
        let boot_tag = BootCommand::Tag {
            last,
            tag,
            flags,
            cipher_blocks,
        };
        // println!("boot tag: {}", hex_str!(&boot_tag.to_bytes(), 4));
        let encrypted_boot_tag = nxp_aes_ctr_cipher(
            &boot_tag.to_bytes(),
            self.keyblob.dek,
            self.parameters.nonce,
            self.boot_tag_offset_blocks() as u32,
        );
        // println!("encr tag: {}", hex_str!(&encrypted_boot_tag, 4));
        // boot tag: 5D010000 00000000 01000000 01000000
        // encr tag: 714D0004 C7177577 157ECFAC D1F7C24B
        // expected: F24D0184 C7177577 157ECFAC D1F7C24B
        // dbg!(&encrypted_boot_tag);
        // dbg!(encrypted_boot_tag.len());
        // panic!();

        Sb21CommandPart {
            encrypted_boot_tag: encrypted_boot_tag[..].try_into().unwrap(),
            unencrypted_hmac_of_encrypted_boot_tag: hmac(self.keyblob.mac, &encrypted_boot_tag),
            unencrypted_hmac_of_encrypted_section: hmac(self.keyblob.mac, &encrypted_section),
            encrypted_section,
        }
    }

    /// TODO: figure out how generic this "key" should be. We want to cover
    /// - on-disk/file keys (cf. RFC 8089: The "file" URI Scheme)
    /// - PKCS#11 keys, so any kind of HSM can be used (cf. RFC 7512: The PKCS #11 URI Scheme)
    /// - possibly other hardware interfaces, such as Tony's yubihsm crate (perhaps: yubihsm:id=<u16>)
    ///   cf: <https://docs.rs/yubihsm/0.37.0/yubihsm/client/struct.Client.html#method.sign_rsa_pkcs1v15_sha256>
    pub fn sign(&self, signing_key: &SigningKey) -> SignedSb21File {
        let header_part = self.header_part();
        let header_bytes = header_part.to_bytes();

        let signature = signing_key.sign(&header_bytes);
        // let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));
        // use sha2::Digest;
        // let mut hasher = sha2::Sha256::new();
        // hasher.update(&header_bytes);
        // let hashed_header = hasher.finalize();
        // let signature = secret_key.sign(padding_scheme, &hashed_header).expect("signatures work");
        // assert_eq!(256, signature.len());

        SignedSb21File {
            unsigned_file: self.clone(),
            header_part,
            command_part: self.command_part(),
            signature: Vec::from(signature.as_bytes()),
        }
    }
}

impl SignedSb21File {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header_part.to_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes.append(&mut self.command_part.to_bytes());
        bytes
    }
}

// impl SignedSb21File {
//     // TODO: Convert `pub fn show` into a proper decoder
//     pub fn read<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
//         let data = fs::read(path.as_ref())
//             .with_context(|| format!("Failed to read data from from {}", path.as_ref().display()))?;

//         if sniff(&data)? != Filetype::Sb21 {
//             return Err(anyhow::anyhow!("Doesn't look like an SB 2.1 file"));
//         }

//     }
// }

pub fn show(filename: &str) -> Result<Vec<u8>> {
    let data = fs::read(filename)
        .with_context(|| format!("Failed to read data from from {}", filename))?;
    trace!("filename: {}", filename);
    trace!("filesize: {}B", data.len());

    let filetype = sniff(&data)?;
    trace!("filetype: {:?}", filetype);

    if let Filetype::Sb21 = filetype {
        let (i, header) = Sb2Header::inner_from_bytes(&data)?; //.unwrap();//.1;//.map_err(|_| anyhow::anyhow!("could not parse SB2 file"))?.1;
        let (i, digest_hmac) = take::<_, _, ()>(32u8)(i)?;
        let (i, keyblob) = Keyblob::from_bytes(i)?;
        let (i, certificate_block_header) = FullCertificateBlockHeader::from_bytes(i)?;
        let (i, certificate_length) = le_u32::<_, ()>(i).unwrap();
        let (i, certificate_data) = take::<_, _, ()>(certificate_length)(i)?;

        let unpadded_signed_data_length = 16 * (6 + 2 + 5 + 2) + 4 + certificate_length + 128;

        let (i, rot_key_hashes) = take::<_, _, ()>(128usize)(i)?;
        let i = if (unpadded_signed_data_length % 16) != 0 {
            take::<_, _, ()>(16u8 - (unpadded_signed_data_length % 16) as u8)(i)?.0
        } else {
            i
        };
        let (i, signature) = take::<_, _, ()>(256usize)(i)?;

        info!(
            "rotkh: {}",
            hex_str!(&crate::pki::Certificates::fingerprint_from_bytes(rot_key_hashes).0)
        );

        // the weird sectionAllignment (sic!)
        info!("SB2 header: \n{:#?}", &header);
        info!("  nonce: {:?}", &header.nonce);
        info!("  tstmp: {}", header.timestamp_microseconds_since_millenium);
        info!("  junk: {}", hexstr!(&header.sb_header_padding));
        info!("HMAC:       \n{:?}", &digest_hmac);
        info!("keyblob:    \n{:?}", &keyblob);
        info!("  DEK: {}", hexstr!(&keyblob.dek));
        info!("  MAC: {}", hexstr!(&keyblob.mac));
        info!("CTH:        \n{:?}", &certificate_block_header);

        let certificate = match X509Certificate::from_der(certificate_data) {
            Ok((rem, cert)) => {
                println!("remainder: {}", hex_str!(rem));
                // assert!(rem.is_empty());
                assert_eq!(
                    cert.tbs_certificate.version,
                    x509_parser::x509::X509Version::V3
                );
                cert
            }
            _ => {
                panic!("invalid certificate");
            }
        };
        // info!("cert: \n{:?}", &certificate);
        println!("certificate length: {}", certificate_length);

        // now let's verify the signature
        // pad 16
        println!(
            "unpadded signed data length: 0x{:x}",
            unpadded_signed_data_length
        );
        // let signed_data_length = signed_data_length + (16 - (signed_data_length % 16));
        let signed_data_length = 16 * ((unpadded_signed_data_length + 15) / 16);

        // let signed_data_length = 0x5f0;
        println!("end of cert data: {:>16x}", hex_str!(&certificate_data));
        println!("signed data length: 0x{:x}", signed_data_length);

        let signed_data_hash = sha256(&data[..signed_data_length as usize]);
        println!("data hash: {}", hex_str!(&signed_data_hash, 4));

        let spki = certificate.tbs_certificate.subject_pki;
        trace!("alg: {:?}", spki.algorithm.algorithm);
        assert_eq!(
            oid_registry::OID_PKCS1_RSAENCRYPTION,
            spki.algorithm.algorithm
        );

        println!("rsa pub key: {:?}", &spki.subject_public_key.data);
        let public_key = rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data)
            .expect("can parse public key");
        println!("signature: {}", hexstr!(&signature));
        let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));
        use rsa::PublicKey;
        public_key
            .verify(padding_scheme, &signed_data_hash, signature)
            .expect("signature valid");
        // let signature = secret_key.sign(padding_scheme, &hashed_image).expect("signatures work");

        let calculated_boot_tag_offset_bytes = signed_data_length + 256;
        assert_eq!(
            calculated_boot_tag_offset_bytes,
            header.boot_tag_offset_blocks * 16
        );

        // alright, BootTag, Hmac, Section
        //
        // here's what happens:
        // - encryption is weird... (big-endian AES-CTR, but with nonce modified by adding
        // block number to little-endian encoding of last nonce-value)
        //
        // - first: encrypted boot tag
        // - then: unencrypted HMAC of encrypted boot tag
        // - then: unencrypted HMAC of encrypted section data (commands and their data)
        // - then: encrypted section data
        //
        // the digest HMAC at the top after image header is HMAC(first HMAC || second HMAC)
        //
        //
        let _boot_tag_offset_blocks = header.boot_tag_offset_blocks;

        let (i, enciphered_boot_tag) = take::<_, _, ()>(16u8)(i)?;
        let calculated_boot_tag_hmac = hmac(keyblob.mac, enciphered_boot_tag);

        let deciphered_boot_tag = nxp_aes_ctr_cipher(
            enciphered_boot_tag,
            keyblob.dek,
            header.nonce,
            header.boot_tag_offset_blocks,
        );

        let (_, boot_tag) = BootCommand::from_bytes(&deciphered_boot_tag)?;
        println!("boot tag: {:?}", &boot_tag);
        // TODO? check cipher blocks

        let (i, hmac_table) = take::<_, _, ()>(64u8)(i)?;

        let (_, (boot_tag_hmac, section_hmac)) =
            tuple((take::<_, _, ()>(32u8), take::<_, _, ()>(32u8)))(hmac_table)?;

        assert_eq!(boot_tag_hmac, calculated_boot_tag_hmac);

        // let (i, section_hmac) = take::<_, _, ()>(32u8)(i)?;

        let enciphered_section = i;

        let calculated_section_hmac = hmac(keyblob.mac, enciphered_section);
        assert_eq!(section_hmac, calculated_section_hmac);

        let deciphered_section = nxp_aes_ctr_cipher(
            enciphered_section,
            keyblob.dek,
            header.nonce,
            header.boot_tag_offset_blocks + 5,
        );

        let calculated_digest_hmac = hmac(keyblob.mac, hmac_table);
        assert_eq!(digest_hmac, calculated_digest_hmac);

        let mut i = deciphered_section.as_ref();
        loop {
            let (j, command) = BootCommand::from_bytes(i)?;
            i = j;
            trace!("command: {:?}", &command);
            if i.is_empty() {
                break;
            }
        }
    }

    println!("crc32(123456789) = 0x{:x}", crc32(b"123456789"));
    todo!();
}

pub struct CertificateBlockHeader {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
}

// #[derive(Clone, Copy, Debug, Eq, PartialEq)]
// pub struct Bcd(u16);

// impl<'a> From<&'a str> for Bcd {
//     fn from(bcd: &'a str) -> Bcd {
//         let number = bcd.parse().unwrap();
//         Bcd(number)
//     }
// }

// impl Into<[u8; 4]> for Bcd {
//     fn into(self) -> [u8; 4] {
//         let bcd = format!("{:04x}", self.0);
//         let bcd: [u8; 4] = bcd.as_bytes().try_into().unwrap();
//         bcd
//     }
// }

/// Version of a firmware.
///
/// The version must be encoded in certain places.
/// To make the API somewhat useable (but admittedly also a bit weirder),
/// we use:
/// - 10 bits for major
/// - 16 bits for minor
/// - 6 bits for patch
///
/// which gives offsets of 22 bits for major and 6 bits for minor in the u32.
///
/// Further, the minor version is at times interpreted as a "calver" encoding
/// days since 2020-01-01. This is optional to use, "semver" works as well.
///
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

// not sure if 999 or 9999
const MAX_BCD: u16 = 9999;

fn bcd(x: u16) -> [u8; 2] {
    assert!(x <= MAX_BCD);
    let mut bcd = [0u8; 2];
    let mut x = x;
    bcd[1] = (x % 10) as _;
    x /= 10;
    bcd[1] |= ((x % 10) << 4) as u8;
    x /= 10;
    bcd[0] = (x % 10) as _;

    bcd
}

impl Version {
    /// For binary consumption, padded with zero bytes
    pub fn to_bytes(&self) -> [u8; 12] {
        // The m_padding0 and m_padding1 fields are used to align other fields and round out the structure size to an even cipher block.
        // These bytes are set to random values when the image is created to add to the “whiteness” of the header for cryptographic
        // purposes.
        let mut binary = [0u8; 12];
        binary[..2].copy_from_slice(&bcd(self.major));
        binary[4..6].copy_from_slice(&bcd(self.minor));
        binary[8..10].copy_from_slice(&bcd(self.patch));

        binary
    }

    /// For end-user consumption, period-separated, not BCD
    pub fn to_semver(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// The minor version component in its interpretation as days since 2020-01-01
    pub fn minor_as_date(&self) -> NaiveDate {
        use chrono::Duration;
        let epoch = NaiveDate::from_ymd(2020, 1, 1);
        epoch + Duration::days(self.minor as _)
    }

    /// For end-user consumption.
    ///
    /// Example: `1:20210624.0`
    pub fn to_calver(&self) -> String {
        format!(
            "{}:{}.{}",
            self.major,
            self.minor_as_date().format("%Y%m%d"),
            self.patch
        )
    }

    pub fn timestamp_micros(&self) -> u64 {
        use chrono::Duration;
        let epoch = NaiveDate::from_ymd(2020, 1, 1).and_hms(12, 0, 0);
        let date = epoch + Duration::days(self.minor as _);

        (date.timestamp_millis() * 1000) as _
    }
}

impl<'a> From<&'a str> for Version {
    fn from(bcd: &'a str) -> Version {
        let parts: Vec<&'a str> = bcd.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3);
        Version {
            major: parts[0].parse().unwrap(),
            minor: parts[1].parse().unwrap(),
            patch: parts[2].parse().unwrap(),
        }
    }
}

impl From<[u8; 4]> for Version {
    fn from(bytes: [u8; 4]) -> Self {
        let version = u32::from_be_bytes(bytes);
        let major = (version >> 22) as _;
        let minor = ((version >> 6) & ((1 << 16) - 1)) as _;
        let patch = (version & ((1 << 6) - 1)) as _;

        Self {
            major,
            minor,
            patch,
        }
    }
}

// todo: be stricter about format errors?
fn version_entry(input: &[u8]) -> nom::IResult<&[u8], u16, ()> {
    let literal_u16 = |x: u16| verify(le_u16, move |y| *y == x);
    map(tuple((u8, u8, literal_u16(0))), |(hi, lo, _padding)| {
        ((hi & 0b1111) as u16) * 100 + (((lo >> 4) * 10 + (lo & 0b1111)) as u16)
    })(input)
}

fn parse_version(i: &[u8]) -> nom::IResult<&[u8], Version, ()> {
    let mut entries = [0u16; 3];
    let (i, ()) = fill(version_entry, &mut entries)(i)?;
    Ok((
        i,
        Version {
            major: entries[0],
            minor: entries[1],
            patch: entries[2],
        },
    ))
}

#[cfg(test)]
pub mod bcd_tests {
    use super::*;

    #[test]
    fn bcd() {
        // let version = Version { major: 123, minor: 456, patch: 999};
        let version = Version::from("123.456.999");
        assert_eq!(
            version,
            Version {
                major: 123,
                minor: 456,
                patch: 999
            }
        );
        let bcd_version = version.to_bytes();
        assert_eq!(
            [0x01, 0x23, 0x00, 0x00, 0x04, 0x56, 0x00, 0x00, 0x09, 0x99, 0x00, 0x00,],
            bcd_version
        );

        let also_version: Version = parse_version(&bcd_version).unwrap().1;
        assert_eq!(version, also_version);
    }
}

// fn from_hex(input: &str) -> Result<u8, std::num::ParseIntError> {
//   u8::from_str_radix(input, 16)
// }

impl serde::Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_semver())
    }
}

impl<'de> serde::Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s: &str = serde::de::Deserialize::deserialize(deserializer)?;
        Ok(s.into())
    }
}

// const FEISTEL_ROUNDS: usize = 5;

// #[derive(Debug)]
// pub struct Aes256KeyWrap {
//     aes: Aes256,
// }

// impl Aes256KeyWrap {
//     pub const KEY_BYTES: usize = 32;
//     pub const MAC_BYTES: usize = 8;

//     pub fn new(key: &[u8; Self::KEY_BYTES]) -> Self {
//         Aes256KeyWrap {
//             aes: aes::Aes256::new(key.into()),
//         }
//     }
// }

#[allow(non_snake_case)]
fn aes_wrap(key: [u8; 32], data: &[u8]) -> Vec<u8> {
    #![allow(non_snake_case)]
    if key.len() % 8 != 0 {
        todo!();
    }
    assert!(data.len() % 8 == 0);
    use aes::cipher::generic_array::GenericArray;
    use aes::{BlockCipher, BlockEncrypt, NewBlockCipher};
    let aes = aes::Aes256::new(&key.into());
    let n = (data.len() as u64) / 8;

    let mut A = u64::from_be_bytes([0xA6u8; 8]);
    // to keep NIST indices, never used
    let mut R = vec![0];
    for (_, P) in (1..=n).zip(data.chunks(8)) {
        R.push(u64::from_be_bytes(P.try_into().unwrap()));
    }

    let mut B = [0u8; 16];
    for j in 0..=5 {
        for i in 1..=n {
            B[..8].copy_from_slice(&A.to_be_bytes());
            B[8..].copy_from_slice(&R[i as usize].to_be_bytes());
            // i.e., B = AES(A | R[i])
            aes.encrypt_block(GenericArray::from_mut_slice(&mut B));

            let t = (n * j + i) as u64;
            A = u64::from_be_bytes(B[..8].try_into().unwrap());
            // i.e., MSB(64, B) ^ t
            A ^= t;
            R[i as usize] = u64::from_be_bytes(B[8..].try_into().unwrap());
        }
    }

    let mut C = Vec::from(A.to_be_bytes());
    for i in 1..=n {
        C.extend_from_slice(&R[i as usize].to_be_bytes());
    }
    C
}

fn aes_unwrap(key: [u8; 32], wrapped: &[u8]) -> Vec<u8> {
    #![allow(non_snake_case)]
    if key.len() % 8 != 0 {
        // return Err(());
        todo!();
    }
    assert!(wrapped.len() % 8 == 0);
    assert!(!wrapped.is_empty());
    use aes::cipher::generic_array::GenericArray;
    use aes::{BlockCipher, BlockDecrypt, NewBlockCipher};
    let aes = aes::Aes256::new(&key.into());
    let n = (wrapped.len() as u64) / 8 - 1;
    let mut A = u64::from_be_bytes(wrapped[..8].try_into().unwrap());
    // to keep NIST indices, never used
    let mut R = vec![0];
    for (_, C) in (1..=n).zip(wrapped.chunks(8).skip(1)) {
        R.push(u64::from_be_bytes(C.try_into().unwrap()));
    }
    let mut B = [0u8; 16];
    for j in (0..=5).rev() {
        for i in (1..=n).rev() {
            let t = (n * j + i) as u64;
            B[..8].copy_from_slice(&(A ^ t).to_be_bytes());
            B[8..].copy_from_slice(&R[i as usize].to_be_bytes());
            // let mut B = ((A ^ t) | R[i as usize]).to_be_bytes();
            aes.decrypt_block(GenericArray::from_mut_slice(&mut B));
            A = u64::from_be_bytes(B[..8].try_into().unwrap());
            R[i as usize] = u64::from_be_bytes(B[8..].try_into().unwrap());
        }
    }
    println!("A = {}", A);
    println!("A = {}", hex_str!(&A.to_be_bytes()));
    // A ?= 'A6 A6 A6 A6 A6 A6 A6 A6'
    assert_eq!(A, 12008468691120727718);
    let mut P = Vec::new();
    for i in 1..=n {
        P.extend_from_slice(&R[i as usize].to_be_bytes());
    }
    P
}

#[cfg(test)]
mod aes_keywrap {
    use super::*;

    #[test]
    fn test() {
        let key = [42; 32];
        let msg: &[u8] = &[];
        assert_eq!(&msg, &aes_unwrap(key, &aes_wrap(key, &msg)).as_slice());
        let msg = [
            1, 2, 3, 4, 5, 6, 7, 8,
            // 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        assert_eq!(&msg, aes_unwrap(key, &aes_wrap(key, &msg)).as_slice());
    }

    #[test]
    fn vectors_rfc_3394() {
        // 256 bit key with...
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();

        // ..128 bit data
        let msg = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let mut expected = String::from("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7");
        expected.retain(|c| !c.is_whitespace());
        assert_eq!(
            hex::decode(expected).unwrap(),
            aes_wrap(kek.clone().try_into().unwrap(), &msg),
        );

        // ...256 bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let msg = hex::decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
            .unwrap();
        let mut expected = String::from(
            "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21",
        );
        expected.retain(|c| !c.is_whitespace());
        assert_eq!(
            hex::decode(expected).unwrap(),
            aes_wrap(kek.clone().try_into().unwrap(), &msg),
        );
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
/// For the proprietary use case, firmware inside the "commands" is encrypted.
/// This works by using a "random" encryption key and a "random" HMAC key, both of which
/// are AES-keywrapped with a "secure boot" key encryption key (denoted SBKEK), which
/// is pre-shared with devices that will receive the SB file.
///
/// In the non-proprietary use-case (or any situation where only authenticity is of
/// interest, not confidentiality), the SBKEK is known, hence also both dek and mac keys.
/// This means that the dek is totally useless, and the mac key can just as well consist
/// of all zeros too. Therefore, we implement `Default` for this struct.
pub struct Keyblob {
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    #[serde(deserialize_with = "hex_deserialize_256")]
    #[serde(default)]
    dek: [u8; 32],
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    #[serde(deserialize_with = "hex_deserialize_256")]
    #[serde(default)]
    mac: [u8; 32],
}

impl Keyblob {
    /// Conor picked this KEK once, all zeros would work too, but why not 101010....101010 ;)
    pub const SBKEK: &'static [u8; 32] = b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA";

    fn to_bytes(&self) -> [u8; 80] {
        let mut keys = [0u8; 64];
        keys[..32].copy_from_slice(&self.dek);
        keys[32..].copy_from_slice(&self.mac);
        let wrapped = aes_wrap(*Self::SBKEK, &keys);
        let mut padded = [0u8; 80];
        padded[..72].copy_from_slice(&wrapped);
        padded
    }

    fn from_bytes(i: &[u8]) -> nom::IResult<&[u8], Self, ()> {
        // if i.len() != 0x60 {
        //     return Err(anyhow::anyhow!("wrong size for SB2 header"));
        // }

        println!("{}", hex_str!(Self::SBKEK));
        let (i, encapsulated) = take(72u8)(i)?;
        let (i, _) = take(8u8)(i)?;
        println!("{}", hex_str!(encapsulated));
        // let unwrapped = b"\x15\x17\xba\x1c\x12\xe2:!\r\xeb\xf1p7\xc3=\x17\x06e:S\xd2\xb7\xf4P-\x11\x01-m\x0f\x8d\x8ey\x17\xd9\xc6x\xc7\xb0\x18\xd9\xf8\x17\xb4fws\"_\xb2\x10\xd3\x9f\x10\xa2\xb5K\x18\xd9\x1d\x1c\xd6\"\x85";
        // println!("wrapped: \n{}", hex_str!(
        //     &Aes256KeyWrap::new(Self::SBKEK).encapsulate(unwrapped).unwrap()));

        // let keywrap = rust_aes_keywrap::Aes256KeyWrap::new(Self::SBKEK);
        // let decapsulated = keywrap.decapsulate(encapsulated, 64).unwrap();
        let decapsulated = aes_unwrap(*Self::SBKEK, encapsulated); //apsulate(encapsulated, 64).unwrap();
                                                                   // let mut nonce = [0u32; 4];
        println!("decapsulated = {}", hex_str!(&decapsulated));
        let mut dek = [0u8; 32];
        let mut mac = [0u8; 32];
        dek.copy_from_slice(&decapsulated[..32]);
        mac.copy_from_slice(&decapsulated[32..]);
        Ok((i, Self { dek, mac }))
    }
}

/// full size: 0x60 = 96 bytes
#[derive(Clone, Debug)]
pub struct Sb2Header {
    nonce: [u32; 4],
    // nonce: [u8; 16],
    header_version_minor: u8,
    flags: u16,
    image_size_blocks: u32,
    boot_tag_offset_blocks: u32,
    boot_section_id: u32,
    certificate_block_header_offset_bytes: u32,
    header_size_blocks: u16,
    keyblob_offset_blocks: u16,
    keyblob_size_blocks: u16,
    max_section_mac_count: u16,
    // flags: Sb2Flags,
    // image_size: usize,
    // boot_tag_offset: usize,
    // certificate_offset: usize,
    // keyblob_offset,
    // max_hmac_table_entries: u16,
    timestamp_microseconds_since_millenium: u64,
    product_version: Version,
    component_version: Version,
    build_number: u32,
    /// For some reason, NXP thinks it's good to pad with random data here instead of zeros
    sb_header_padding: [u8; 4],
}

// struct certificate_block_header_t {
//     uint8_t  signature[4];                  //!< Always set to 'cert'
//     uint16_t headerMajorVersion;            //!< Set to 1
//     uint16_t headerMinorVersion;            //!< Set to 0
//     uint32_t headerLengthInBytes;           //!< Starting from the signature and not including the certificate table.
//     uint32_t flags;                         //!< Reserved for future use.
//     uint32_t buildNumber;                   //!< Build number of the user code. Allows user to prevent reverting to old versions
//     uint32_t totalImageLengthInBytes;       //!< Length in bytes of the signed data
//     uint32_t certificateCount;              //!< Must be greater than 0
//     uint32_t certificateTableLengthInBytes; //!< Total length in bytes of the certificate table
// };

#[derive(Clone, Debug)]
pub struct FullCertificateBlockHeader {
    header_length_in_bytes: u32,
    build_number: u32,
    total_image_length_in_bytes: u32,
    certificate_count: u32,
    certificate_table_length_in_bytes: u32,
}

impl FullCertificateBlockHeader {
    fn to_bytes(&self) -> [u8; 2 * 16] {
        let mut bytes = Vec::from(b"cert".as_ref());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.header_length_in_bytes.to_le_bytes());
        // todo: what is flags?
        // todo!("the following is flags, what is it?");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&self.build_number.to_le_bytes());
        bytes.extend_from_slice(&self.total_image_length_in_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.certificate_count.to_le_bytes());
        bytes.extend_from_slice(&self.certificate_table_length_in_bytes.to_le_bytes());

        let mut raw_bytes = [0u8; 32];
        raw_bytes.copy_from_slice(&bytes);
        raw_bytes
    }

    fn from_bytes(i: &[u8]) -> nom::IResult<&[u8], Self, ()> {
        // let literal_u8 = |x: u8| verify(u8, move |y| *y == x);
        let literal_u16 = |x: u16| verify(le_u16, move |y| *y == x);
        let literal_u32 = |x: u32| verify(le_u32, move |y| *y == x);

        let (i, _signature) = tag("cert")(i)?;
        let (i, _header_major_version) = literal_u16(1)(i)?;
        let (i, _header_minor_version) = literal_u16(0)(i)?;
        let (i, header_length_in_bytes) = le_u32(i)?;
        let (i, _flags) = le_u32(i)?;
        let (i, build_number) = le_u32(i)?;
        let (i, total_image_length_in_bytes) = le_u32(i)?;
        let (i, certificate_count) = literal_u32(1)(i)?;
        let (i, certificate_table_length_in_bytes) = le_u32(i)?;

        Ok((
            i,
            Self {
                header_length_in_bytes,
                build_number,
                total_image_length_in_bytes,
                certificate_count,
                certificate_table_length_in_bytes,
            },
        ))
    }
}

impl Sb2Header {
    /// 96 bytes
    pub const LEN: usize = 96;
    pub fn from_bytes(i: &[u8]) -> Result<Self> {
        let (remainder_len, header) =
            Self::inner_from_bytes(i).map(|(remainder, header)| (remainder.len(), header))?;
        match remainder_len {
            0 => Ok(header),
            _ => Err(anyhow::anyhow!("spurious bytes")),
        }
    }

    /// 96 bytes
    pub fn len(&self) -> usize {
        Self::LEN
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn product_version(&self) -> Version {
        self.product_version
    }

    fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut bytes = Vec::new();
        for entry in self.nonce.iter() {
            bytes.extend_from_slice(&entry.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(b"STMP");
        bytes.push(2);
        bytes.push(self.header_version_minor);
        bytes.extend_from_slice(&self.flags.to_le_bytes());
        bytes.extend_from_slice(&self.image_size_blocks.to_le_bytes());
        bytes.extend_from_slice(&self.boot_tag_offset_blocks.to_le_bytes());
        bytes.extend_from_slice(&self.boot_section_id.to_le_bytes());
        bytes.extend_from_slice(&self.certificate_block_header_offset_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.header_size_blocks.to_le_bytes());
        bytes.extend_from_slice(&self.keyblob_offset_blocks.to_le_bytes());
        bytes.extend_from_slice(&self.keyblob_size_blocks.to_le_bytes());
        bytes.extend_from_slice(&self.max_section_mac_count.to_le_bytes());
        bytes.extend_from_slice(b"sgtl");
        bytes.extend_from_slice(&self.timestamp_microseconds_since_millenium.to_le_bytes());
        bytes.extend_from_slice(&self.product_version.to_bytes());
        bytes.extend_from_slice(&self.component_version.to_bytes());
        bytes.extend_from_slice(&self.build_number.to_le_bytes());
        bytes.extend_from_slice(&self.sb_header_padding);

        let mut array = [0u8; 96];
        array.copy_from_slice(&bytes);
        array
    }

    fn inner_from_bytes(i: &[u8]) -> nom::IResult<&[u8], Self, ()> {
        // if i.len() != 0x60 {
        //     return Err(anyhow::anyhow!("wrong size for SB2 header"));
        // }
        let mut nonce = [0u32; 4];
        let (i, ()) = fill(le_u32, &mut nonce)(i)?;
        // let mut nonce = [0u8; 16];
        // let (i, ()) = fill(u8, &mut nonce)(i)?;

        let (i, _reserved) = take(4u8)(i)?;

        let (i, _signature) = tag("STMP")(i)?;

        // are these not somewhere in `nom` already??
        let literal_u8 = |x: u8| verify(u8, move |y| *y == x);
        let literal_u16 = |x: u16| verify(le_u16, move |y| *y == x);
        let literal_u32 = |x: u32| verify(le_u32, move |y| *y == x);

        // header_version_major should be 2u8
        let (i, _) = literal_u8(2u8)(i)?;
        // header_version_major should be 0u8 or 1u8
        let (i, header_version_minor) = alt((literal_u8(0), literal_u8(1)))(i)?;

        let (i, flags) = le_u16(i)?;
        let (i, image_size_blocks) = le_u32(i)?;
        let (i, boot_tag_offset_blocks) = le_u32(i)?;
        let (i, boot_section_id) = literal_u32(0)(i)?;
        let (i, certificate_block_header_offset_bytes) = le_u32(i)?;
        let (i, header_size_blocks) = literal_u16(6)(i)?;
        let (i, keyblob_offset_blocks) = literal_u16(8)(i)?;
        let (i, keyblob_size_blocks) = literal_u16(5)(i)?;
        let (i, max_section_mac_count) = literal_u16(1)(i)?;
        let (i, _signature2) = tag("sgtl")(i)?;
        let (i, timestamp_microseconds_since_millenium) = le_u64(i)?;
        let (i, product_version) = parse_version(i)?;
        let (i, component_version) = parse_version(i)?;
        let (i, build_number) = le_u32(i)?;
        let mut sb_header_padding = [0u8; 4];
        let (i, ()) = fill(u8, &mut sb_header_padding)(i)?;
        // nom::exact!(i, take(4u8));

        Ok((
            i,
            Self {
                nonce,
                header_version_minor,
                flags,
                image_size_blocks,
                boot_tag_offset_blocks,
                boot_section_id,
                certificate_block_header_offset_bytes,
                header_size_blocks,
                keyblob_offset_blocks,
                keyblob_size_blocks,
                max_section_mac_count,
                timestamp_microseconds_since_millenium,
                product_version,
                component_version,
                build_number,
                sb_header_padding,
            },
        ))
    }
}
