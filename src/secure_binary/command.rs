use core::convert::{TryFrom, TryInto};
use std::fs;
use serde::{Deserialize, Serialize};

use nom::{
    // branch::alt,
    bytes::complete::{
        // tag, take, take_while_m_n,
        take,
    },
    // combinator::{
    //     map, value, verify,
    // },
    // multi::{
    //     fill,
    // },
    number::complete::{
        u8, le_u16, le_u32, //le_u64, le_u128,
    },
    sequence::tuple,
};

use crate::crypto::crc32;
use crate::util::is_default;

const START_OF_PROTECTED_FLASH: u32 = 0x9_DE00;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BootTag {
    Nop = 0,
    Tag = 1,
    Load = 2,
    Fill = 3,
    Jump = 4,
    Call = 5,
    ChangeBootMode = 6,
    Erase = 7,
    Reset = 8,
    MemoryEnable = 9,
    ProgramPersistentBits = 0xA,
    CheckFirmwareVersion = 0xB,
    KeystoreToNonvolatile = 0xC,
    KeystoreFromNonvolatile = 0xD,
}

// struct boot_command_t
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RawBootCommand {
    pub checksum: u8,
    pub tag: u8,
    pub flags: u16,
    pub address: u32,
    pub count: u32,
    pub data: u32,
}

impl RawBootCommand {
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buffer = Vec::new();
        buffer.push(0);
        buffer.push(self.tag);
        buffer.extend_from_slice(self.flags.to_le_bytes().as_ref());
        buffer.extend_from_slice(self.address.to_le_bytes().as_ref());
        buffer.extend_from_slice(self.count.to_le_bytes().as_ref());
        buffer.extend_from_slice(self.data.to_le_bytes().as_ref());
        let checksum = buffer[1..].iter().fold(0x5au8, |acc, x| acc.wrapping_add(*x));
        buffer[0] = checksum;
        buffer.try_into().unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ()> {
        let (i, (
            checksum,
            tag,
            flags,
            address,
            count,
            data,
        )) = tuple((
            u8,
            u8,
            le_u16,
            le_u32,
            le_u32,
            le_u32,
        ))(bytes)?;

        // by previous, bytes.len() >= 16
        info!("raw boot command: {}", hex_str!(&bytes[..16]));
        let calculated_checksum = bytes[1..16].iter().fold(0x5au8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(calculated_checksum, checksum);

        Ok((i, Self { checksum, tag, flags, address, count, data }))
    }
}

/// Commands used to define SB2.1 files
///
/// Currently, we only need to erase and load (partial) files.
///
/// ### Example
/// Since there does not seem to exit a command to enter the bootloader, but
/// a corrupt / missing firmware makes the MCU enter the bootloader, one way
/// to do so is the following specification, which erases the first flash page.
/// ```ignore
/// [[commands]]
/// cmd = "Erase"
/// start = 0
/// end = 512
/// ```
///
/// ### Example
/// To securely flash firmware, it is advised to write the first page last, so that
/// if flashing goes wrong or is interrupted, the MCU stays in the bootloader on next boot.
/// ```ignore
/// [[commands]]
/// cmd = "Erase"
/// start = 0
/// end = 0x8_9800
///
/// [[commands]]
/// ## write firmware, skipping first flash page
/// cmd = "Load"
/// file = "example.sb2"
/// src = 512
/// dst = 512
///
/// [[commands]]
/// ## write first flash page of firmware
/// cmd = "Load"
/// file = "example.sb2"
/// len = 512
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "cmd")]
pub enum BootCommandDescriptor {
    /// Maps to `BootCommand::EraseRegion`, but `start` and `end` are given in bytes.
    Erase { start: u32, end: u32 },
    /// Load (part) of the data reference in `source` to flash.
    ///
    /// The syntax is such that if source data and destination flash were slices
    /// `src: &[u8]` and `dst: &mut [u8]`, this command would do:
    /// ```ignore
    /// let src_len = src.len() - cmd.src;
    /// let len = cmd.len.unwrap_or(src_len);
    /// dst[cmd.dst..][..len].copy_from_slice(&src[cmd.src..][..len]);
    /// ```
    Load {
        file: String,

        /// source offset in bytes (default 0)
        #[serde(default)]
        #[serde(skip_serializing_if = "is_default")]
        src: u32,

        /// destination offset in bytes (default 0)
        #[serde(default)]
        #[serde(skip_serializing_if = "is_default")]
        dst: u32,

        /// number of bytes to copy
        // #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        len: Option<u32>,
    },

    CheckNonsecureFirmwareVersion {
        version: u32,
    },

    CheckSecureFirmwareVersion {
        version: u32,
    },
}

impl<'a> TryFrom<&'a BootCommandDescriptor> for BootCommand {
    type Error = anyhow::Error;

    fn try_from(cmd: &'a BootCommandDescriptor) -> anyhow::Result<BootCommand> {

        use BootCommandDescriptor::*;
        Ok(match cmd {
            Erase { start, end } => BootCommand::EraseRegion { address: *start, bytes: core::cmp::max(0, *end - *start) },
            Load { file, src, dst, len } => {
                let image = fs::read(file)?;

                if let Some(len) = len {
                    if (image.len() as u32) < len + src {
                        return Err(anyhow::anyhow!("image too small!"));
                    }

                }
                let src_len = image.len() - *src as usize;
                let len = len.unwrap_or(src_len as u32) as usize;
                let data = Vec::from(&image[*src as usize..][..len]);
                BootCommand::Load { address: *dst, data }

            }
            CheckNonsecureFirmwareVersion { version } => BootCommand::CheckNonsecureFirmwareVersion { version: *version },
            CheckSecureFirmwareVersion { version } => BootCommand::CheckSecureFirmwareVersion { version: *version },
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// The LPC55xx ROM loader provides the support for the following bootloader commands:
// * WriteMemory, FillMemory, ConfigureMemory, FlashEraseAll, FlashEraseRegion,
// SB 2.1 introduces two new commands that can be used to prevent firmware roll-back:
// * SecureFirmwareVersion, NonsecureFirmwareVersion
pub enum BootCommand {
    // example: 5A|00|0000|00000000|00000000|00000000
    Nop,
    // example: F3|01|0180|00000000|B2640000|01000000
    Tag { last: bool, tag: u32, flags: u32, cipher_blocks: u32 },
    // example: 8F|02|0000|00000000|00020000|A6D9585A
    Load { address: u32, data: Vec<u8> },
    // example?
    /// See ELFTOSB document for explanations of what is supposed to happen when
    /// address is not on a word boundary.
    ///
    /// In any case, if a byte is supposed to be repeated, it must be replicated
    /// four times in the `pattern`, e.g. "fill with 0xF1" => pattern = `0xf1f1_f1f1`.
    Fill { address: u32, bytes: u32, pattern: u32 },
    // example?
    EraseAll,
    // example: 01|07|0000|00000000|00980800|00000000
    // NB: this command is interpreted as "erase all flash sectors that intersect with the
    // specified region"
    EraseRegion { address: u32, bytes: u32 },
    CheckSecureFirmwareVersion { version: u32 },
    CheckNonsecureFirmwareVersion { version: u32 },
}

impl BootCommand {
    pub fn to_bytes(&self) -> Vec<u8> {
        use BootCommand::*;
        let mut cmd: RawBootCommand = Default::default();
        match self {
            Nop => {
                cmd.tag = BootTag::Nop as u8;
                Vec::from(cmd.to_bytes().as_ref())
            }
            Tag { last, tag, flags, cipher_blocks } => {
                cmd.tag = BootTag::Tag as u8;
                if *last {
                    cmd.flags = 1;
                } else {
                    cmd.flags = 0x8001;
                }
                cmd.address = *tag;
                cmd.data = *flags;
                cmd.count = *cipher_blocks;
                Vec::from(cmd.to_bytes().as_ref())
            }
            Load { address, data } => {
                if address + data.len() as u32 >= START_OF_PROTECTED_FLASH {
                    panic!("It is nearly always a mistake to write into the protected flash area");
                }
                //           CRC|tag|flags  addr     count    data
                // expected:  54|02|0000    00000000 78090000 7E976AF8
                // generated: 03|02|0000    00000000 78090000 FD96E7AC (...)
                cmd.tag = BootTag::Load as u8;
                cmd.address = *address;
                cmd.count = data.len() as u32;
                // this takes advantage of the fact that our crc32
                // adds "padding till multiple of 16 bytes with zeros"
                // to the CRC calculation.
                cmd.data = crc32(data);
                let blocks = (data.len() + 15) / 16;
                // let blocks = (data.len() + 3) / 4;
                // let padding = blocks*16 - data.len();
                let mut vec = Vec::from(cmd.to_bytes().as_ref());
                println!("generated {}", &hex_str!(&vec, 4));
                // panic!();
                vec.extend_from_slice(data.as_ref());
                // add padding
                // NB: NXP says to fill with random bytes, I don't see the point.
                // We're not actually encrypting anyway, and AES is supposed to be a... cipher ;)
                // vec.resize(32 + 16*blocks, 0);
                // vec.resize(16 + 4*blocks, 0);
                vec.resize(16 + 16*blocks, 0);
                vec
            }
            EraseAll => {
                cmd.tag = BootTag::Erase as u8;
                cmd.flags = 1;
                Vec::from(cmd.to_bytes().as_ref())
            }
            EraseRegion { address, bytes } => {
                if address + bytes >= START_OF_PROTECTED_FLASH {
                    panic!("It is nearly always a mistake to erase the protected flash area");
                }
                cmd.tag = BootTag::Erase as u8;
                cmd.address = *address;
                cmd.count = *bytes;
                Vec::from(cmd.to_bytes().as_ref())
            }
            CheckSecureFirmwareVersion { version } => {
                cmd.tag = BootTag::CheckFirmwareVersion as u8;
                // according to nxp/spsdk
                cmd.address = 0;
                cmd.count = *version;
                Vec::from(cmd.to_bytes().as_ref())
            }
            CheckNonsecureFirmwareVersion { version } => {
                cmd.tag = BootTag::CheckFirmwareVersion as u8;
                cmd.address = 1;
                cmd.count = *version;
                Vec::from(cmd.to_bytes().as_ref())
            }
            _ => todo!(),
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ()> {
        let (i, raw) = RawBootCommand::from_bytes(bytes)?;
        Ok(match raw.tag {
            // BootTag::Nop => {
            0 => {
                // todo? check everything zero except checksum
                (i, Self::Nop)
            }
            // BootTag::Tag => {
            1 => {
                (i, Self::Tag {
                    last: (raw.flags & 1) != 0,
                    tag: raw.address,
                    flags: raw.data,
                    cipher_blocks: raw.count,
                })
            }
            // BootTag::Load => {
            2 => {
                let blocks = (raw.count as usize + 15) / 16;
                let (i, data_ref) = take(blocks * 16)(i)?;
                let data = Vec::from(&data_ref[..raw.count as usize]);
                if raw.count as usize != data_ref.len() {
                    info!("surplus random bytes skipped when reading: {}", hex_str!(&data_ref[raw.count as usize..]));
                }
                // verify "CRC-32" calculation:
                // raw.data == CRC over entire contents of `data_ref`, including padding
                let calculated_crc = crc32(data_ref);
                assert_eq!(calculated_crc, raw.data);
                (i, Self::Load {
                    address: raw.address,
                    // bytes: data.len(),
                    data,
                })
            }
            // BootTag::Fill => {
            3 => {
                (i, Self::Fill {
                    address: raw.address,
                    bytes: raw.count,
                    pattern: raw.data,
                })
            }
            // BootTag::Erase => {
            7 => {
                let erase_all = (raw.flags & 1) != 0;
                let disable_flash_security_state = (raw.flags & 2) != 0;
                // not supported yet
                assert!(!disable_flash_security_state);
                let memory_controller_id = (raw.flags >> 8) & 0b1111;
                // expect "internal" flash"
                assert_eq!(memory_controller_id, 0x0);

                if erase_all {
                    // raw.address and raw.count are ignored
                    (i, Self::EraseAll)
                } else {
                    (i, Self::EraseRegion {
                        address: raw.address,
                        bytes: raw.count,
                    })
                }
            }
            // BootTag::CheckFirmwareVersion => {
            0xB => {
                // header.m_address = ENDIAN_HOST_TO_LITTLE_U32((uint32_t)m_versionType);
                // header.m_count = ENDIAN_HOST_TO_LITTLE_U32(m_version);
                // SecureVersion = 0x0,
                // NonSecureVersion = 0x1,
                let nonsecure_version = (raw.address & 1) != 0;
                // header.m_address = ENDIAN_HOST_TO_LITTLE_U32((uint32_t)m_versionType);
                // header.m_count = ENDIAN_HOST_TO_LITTLE_U32(m_version);
                if nonsecure_version {
                    (i, Self::CheckNonsecureFirmwareVersion { version: raw.count })
                } else {
                    (i, Self::CheckSecureFirmwareVersion { version: raw.count })
                }
            }
            _ => todo!("implement other boot commands"),
        })
    }
}

