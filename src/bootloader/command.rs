use core::convert::TryFrom;

use serde::{Deserialize, Serialize};

use super::property::Property;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Command {
    EraseFlashAll,
    EraseFlash { address: usize, length: usize },
    ReadMemory { address: usize, length: usize },
    WriteMemory { address: usize, data: Vec<u8> },
    /// Converts the words to little-endian, then delegates to `WriteMemory`
    WriteMemoryWords { address: usize, words: Vec<u32> },
    FillMemory,
    /// cf. <https://www.nxp.com/docs/en/application-note/AN12527.pdf>
    ConfigureMemory { address: usize },
    FlashSecurityDisable,
    // there is actually a second parameter, Memory ID
    // 0 = internal flash
    // 1 = QSPI0 memory (unused for LPC55)
    GetProperty ( Property ),
    ReceiveSbFile { data: Vec<u8> },
    Call,
    Reset,
    FlashReadResource,
    Keystore(KeystoreOperation),
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, enum_iterator::IntoEnumIterator, Ord, PartialEq, PartialOrd)]
pub enum CommandTag {
    EraseFlashAll = 0x01,
    EraseFlash = 0x02,
    ReadMemory = 0x03,
    WriteMemory = 0x04,
    FillMemory = 0x05,
    FlashSecurityDisable = 0x06,
    GetProperty = 0x07,
    ReceiveSbFile = 0x08,
    Execute = 0x09,
    Call = 0x0A,
    Reset = 0x0B,
    SetProperty = 0x0C,
    EraseFlashAllUnlock = 0x0D,
    FlashProgramOnce = 0x0E,
    FlashReadOnce = 0x0F,
    FlashReadResource = 0x10,
    ConfigureMemory = 0x11,
    ReliableUpdate = 0x12,
    GenerateKeyBlob = 0x13,
    Keystore = 0x15,
    ConfigureI2c = 0xC1,
    ConfigureSpi = 0xC2,
    ConfigureCan = 0xC3,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// Signifies which of the three cases of the protocol is used.
///
/// Note that there is no situation where both command and response have a data phase.
pub enum DataPhase {
    None,
    CommandData(Vec<u8>),
    ResponseData,
}

impl DataPhase {
    pub fn has_command_data(&self) -> bool {
        matches!(self, DataPhase::CommandData(_))
    }
}

impl Command {
    pub fn data_phase(&self) -> DataPhase {
        use CommandTag as Tag;
        match (self, self.tag()) {
            (_, Tag::ReadMemory) => DataPhase::ResponseData,
            (_, Tag::EraseFlash) => DataPhase::None,
            (_, Tag::EraseFlashAll) => DataPhase::None,
            (_, Tag::GetProperty) => DataPhase::None,
            (_, Tag::Reset) => DataPhase::None,
            (_, Tag::ConfigureMemory) => DataPhase::None,

            (Command::WriteMemory { address: _, data }, _) => DataPhase::CommandData(data.clone()),
            (Command::WriteMemoryWords { address: _, words }, _) => {
               use std::io::Write;
               let mut bytes = Vec::with_capacity(words.len() * 4);
               let cursor = &mut bytes;

               for word in words.iter() {
                   cursor.write_all(&word.to_le_bytes()).unwrap();
               }

                DataPhase::CommandData(bytes)
            },
            (Command::ReceiveSbFile { data }, _) => DataPhase::CommandData(data.clone()),

            (Command::Keystore(KeystoreOperation::Enroll), _) => DataPhase::None,
            (Command::Keystore(KeystoreOperation::ReadKeystore), _) => DataPhase::ResponseData,
            (Command::Keystore(KeystoreOperation::SetKey { key: _, data }), _) => DataPhase::CommandData(data.clone()),
            (Command::Keystore(KeystoreOperation::GenerateKey { key: _, len: _ }), _) => DataPhase::None,
            (Command::Keystore(KeystoreOperation::WriteNonVolatile), _) => DataPhase::None,
            (Command::Keystore(KeystoreOperation::ReadNonVolatile), _) => DataPhase::None,

            _ => todo!()
        }
    }

    pub fn parameters(&self) -> Vec<u32> {
        use Command::*;
        match self.clone() {
            GetProperty(property) => {
                vec![property as u8 as u32, 0]
            }
            ReadMemory { address, length } => {
                // PyMBOOT is kinda bugged here, it signals sending 3 parameters
                // (but the third one is set to zero)
                vec![address as u32, length as u32]
            }
            EraseFlash { address, length } => {
                vec![address as u32, length as u32]
            }
            EraseFlashAll => {
                vec![]
            }
            WriteMemory { address, data } => {
                vec![address as u32, data.len() as u32, 0]
            }
            WriteMemoryWords { address, words } => {
                vec![address as u32, (words.len() * 4) as u32, 0]
            }
            ConfigureMemory { address } => {
                vec![0, address as u32]
            }
            ReceiveSbFile { data } => {
                vec![data.len() as _]
            }
            Reset => {
                vec![]
            }
            Keystore(operation) => {
                use KeystoreOperation::*;
                match operation.clone() {
                    Enroll => {
                        vec![u32::from(&operation)]
                    }
                    ReadKeystore => {
                        vec![u32::from(&operation)]
                    }
                    SetKey { key, data } => {
                        vec![u32::from(&operation), key as u32, data.len() as u32]
                    }
                    GenerateKey { key, len } => {
                        vec![u32::from(&operation), key as u32, len]
                    }
                    WriteNonVolatile => {
                        vec![u32::from(&operation), 0]
                    }
                    ReadNonVolatile => {
                        vec![u32::from(&operation), 0]
                    }
                    _ => todo!()

                }
            }
            _ => todo!()
        }
    }

    pub fn tag(&self) -> CommandTag {
        use Command::*;
        use CommandTag as Tag;
        match *self {
            EraseFlashAll => Tag::EraseFlashAll,
            EraseFlash { address: _, length: _ } => Tag::EraseFlash,
            ReadMemory { address: _, length: _ } => Tag::ReadMemory,
            WriteMemory { address: _, data: _ } => Tag::WriteMemory,
            WriteMemoryWords { address: _, words: _} => Tag::WriteMemory,
            FillMemory => Tag::FillMemory,
            FlashSecurityDisable => Tag::FlashSecurityDisable,
            GetProperty(_) => Tag::GetProperty,
            ReceiveSbFile { data: _ } => Tag::ReceiveSbFile,
            Call => Tag::Call,
            Reset => Tag::Reset,
            FlashReadResource => Tag::FlashReadResource,
            ConfigureMemory { address: _ } => Tag::ConfigureMemory,
            Keystore(_) => Tag::Keystore,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HidHeader {
    report_id: ReportId,
    packet_length: usize,
}

impl Command {
    /// Not yet quite clear what comes from HID spec, and what's NXP framing command packets in HID.
    pub fn hid_packet(&self) -> Vec<u8> {
        let command_packet = self.command_packet();
        // dbg!(to_hex_string(&command_packet.clone()));

        let mut header = [0u8; 4];
        // pyMBoot does: `pack('<2BH', report_id, 0x00, data_len)`
        // MCU Bootloader 2.5.0 RM rev 1. (05/2018) says: 1 byte report ID, 2 bytes packet length
        // It seems pyMBoot is right, and the RM is wrong
        header[0] = ReportId::Command as u8;
        header[2..].copy_from_slice(&(command_packet.len() as u16).to_le_bytes());

        // umm...
        let mut hid_packet = Vec::new();
        hid_packet.extend_from_slice(&header);
        hid_packet.extend_from_slice(&command_packet);
        hid_packet
    }

    pub fn header(&self) -> [u8; 4] {
        [
            // command tag
            self.tag() as u8,
            // data phase flag
            self.data_phase().has_command_data() as u8,
            // reserved
            0,
            // number of parameters
            self.parameters().len() as u8,
        ]
    }

    /// The command packet carries a 32-bit command header and a list of 32-bit little-endian parameters.
    ///
    /// In total, it is always 32 bytes long. This implies that there can be at most 7 parameters.
    fn command_packet(&self) -> Vec<u8> {
        let params = self.parameters();
        assert!(params.len() <= 7);

        let mut packet = Vec::new();

        packet.extend_from_slice(&self.header());
        params.iter().for_each(|param| { packet.extend_from_slice(param.to_le_bytes().as_ref()) } );
        packet.resize(32, 0);

        packet
    }

    // todo:
    // fn data_packets(&self) -> Iterator
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, enum_iterator::IntoEnumIterator, Ord, PartialEq, PartialOrd)]
pub enum ResponseTag {
    Generic = 0xA0,
    ReadMemory = 0xA3,
    GetProperty = 0xA7,
    FlashReadOnce = 0xAF,
    FlashReadResource = 0xB0,
    Keystore = 0xB5,
}

impl TryFrom<u8> for ResponseTag {
    type Error = u8;
    fn try_from(byte: u8) -> Result<ResponseTag, u8> {
        use ResponseTag::*;
        Ok(match byte {
            0xA0 => Generic,
            0xA3 => ReadMemory,
            0xA7 => GetProperty,
            0xAF => FlashReadOnce,
            0xB0 => FlashReadResource,
            0xB5 => Keystore,
            _ => return Err(byte),
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Response {
    Generic,
    Data(Vec<u8>),
    // todo: model the properties
    GetProperty(Vec<u32>),
    ReadMemory(Vec<u8>),
}

impl Response {
    pub fn tag(&self) -> ResponseTag {
        use Response::*;
        use ResponseTag as Tag;
        match *self {
            Generic => Tag::Generic,
            Data(_) => Tag::Generic,
            GetProperty(_) => Tag::GetProperty,
            ReadMemory(_) => Tag::ReadMemory,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, enum_iterator::IntoEnumIterator, Ord, PartialEq, PartialOrd)]
// todo: rename to HidReportId? place in `mod hid` submodule?
pub enum ReportId {
    Command = 1,
    Response = 3,
    CommandData = 2,
    ResponseData = 4,
}

impl TryFrom<u8> for ReportId {
    type Error = u8;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        use ReportId::*;
        Ok(match byte {
            1 => Command,
            2 => CommandData,
            3 => Response,
            4 => ResponseData,
            _ => return Err(byte),
        })
    }
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Version {
    pub mark: Option<char>,
    pub major: u8,
    pub minor: u8,
    pub fixation: u8,
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        if let Some(mark) = self.mark {
            write!(f, "{}", mark)?;
        }
        write!(f, "{}.{}.{}", self.major, self.minor, self.fixation)
    }
}

impl From<u32> for Version {
    fn from(value: u32) -> Self {
        Self {
            // mark: char::from_u32(value >> 24),
            mark: {
                let candidate = (value >> 24) as u8 as char;
                if candidate.is_ascii_uppercase() {
                    Some(candidate)
                } else {
                    None
                }
            },
            major: (value >> 16) as u8,
            minor: (value >> 8) as u8,
            fixation: value as u8,
            // mark: {
            //     let candidate = value as u8 as char;
            //     if candidate.is_ascii_uppercase() {
            //         Some(candidate)
            //     } else {
            //         None
            //     }
            // },
            // major: (value >> 8) as u8,
            // minor: (value >> 16) as u8,
            // fixation: (value >> 24) as u8,
        }
    }
}

// #[derive(Copy, Clone, Debug)]
// pub enum Peripheral {
//     Uart = 0x01,
//     I2c = 0x02,
//     Spi = 0x04,
//     Can = 0x08,
//     UsbHid = 0x10,
//     UsbCdc = 0x20,
//     UsbDfu = 0x40,
// }

// impl From<u8> for Peripheral {
//     fn from(value: u8) -> Self {
//         use Peripheral::*;
//         match value {
//             0x01 => Uart,
//             0x02 => Uart,
//             0x04 => Uart,
//             0x08 => Uart,
//             0x01 => Uart,

// }

#[derive(Copy, Clone, Debug)]
pub enum FlashReadMargin {
    Normal,
    User,
    Factory,
    // Unknown(u8),
}

impl From<FlashReadMargin> for u8 {
    fn from(frm: FlashReadMargin) -> u8 {
        use FlashReadMargin::*;
        match frm {
            Normal => 0,
            User => 1,
            Factory => 2,
            // Unknown(unknown) => unknown,
        }

    }
}

impl core::convert::TryFrom<u8> for FlashReadMargin {
    type Error = u8;
    fn try_from(byte: u8) -> core::result::Result<Self, u8> {
        use FlashReadMargin::*;
        Ok(match byte {
            0 => Normal,
            1 => User,
            2 => Factory,
            _ => return Err(byte),
        })
    }
}

// impl From<Property> for u8 {
//     fn from(property: Property) -> u8 {
//         use Property::*;
//         match property {
//             CurrentVersion => 0x01,
//             AvailablePeripherals = 0x02,
//             FlashStartAddress = 0x03,
//             FlashSize => 0x04,
//             FlashSectorSize = 0x05,
//             FlashBlockCount = 0x06,
//             AvailableCommands = 0x07,
//             CrcCheckStatus = 0x08,
//             LastError = 0x09,
//             VerifyWrites = 0x0A,
//             MaxPacketSize = 0x0B,
//             ReservedRegions = 0x0C,
//             ValidateRegions = 0x0D,
//             RamStartAddress = 0x0E,
//             RamSize = 0x0F,
//             SystemDeviceIdent = 0x10,
//             FlashSecurityState = 0x11,
//             UniqueDeviceIdent = 0x12,
//             FlashFacSupport = 0x13,
//             FlashAccessSegmentSize = 0x14,
//             FlashAccessSegmentCount = 0x15,
//             FlashReadMargin = 0x16,
//             QspiInitStatus = 0x17,
//             TargetVersion = 0x18,
//             ExternalMemoryAttributes = 0x19,
//             ReliableUpdateStatus = 0x1A,
//             FlashPageSize = 0x1B,
//             IrqNotifierPin = 0x1C,
//             ProtectedFlashKeystoreUpdateOpt = 0x1D,
//         }
//     }
// }

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// numbers can be found in UM, Chap 7.3.2 "Key descriptions"
pub enum Key {
    PrinceRegion0 = 7,
    PrinceRegion1 = 8,
    PrinceRegion2 = 9,
    /// used by bootloader to decrypt SB2.1 firmware images
    SecureBootKek = 3,
    UniqueDeviceSecret = 12,
    /// not used by bootloader. idea is to use as pre-shared secret for user/firmware/apps etc.
    UserPsk = 11,
}

// unfortunately duplicated in cli.rs, for why see there
pub const KEYSTORE_KEY_NAMES: [&str; 6] = [
    "secure-boot-kek",
    "user-key",
    "unique-device-secret",
    "prince-region-0",
    "prince-region-1",
    "prince-region-2",
];

impl TryFrom<&str> for Key {
    type Error = String;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        use Key::*;
        Ok(match name {
            "prince-region-0" => PrinceRegion0,
            "prince-region-1" => PrinceRegion1,
            "prince-region-2" => PrinceRegion2,
            "secure-boot-kek" => SecureBootKek,
            "unique-device-secret" => UniqueDeviceSecret,
            "user-key" => UserPsk,
            _ => return Err(name.to_string())
        })
    }
}

#[repr(u8)]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "sub-cmd")]
// naming taken from docs, could also be called Subcommand, or even Command
/// This is the interface definition to a somewhat limited bootloader API,
/// that then operates on the actual PFR data and PUF periphreal.
///
/// The operations Enroll, SetKey, GenerateKey create activation codes or key codes,
/// which the bootloader keeps in RAM and only writes to PFR once WriteNonVolatile is
/// called. If this is not done, on reboot, the PUF is unenrolled again, or the keys
/// are not set anymore.
///
/// It doesn't however seem possible to set/generate new keys after reboot without
/// re-enrolling PUF, calling set/generate key results in a `Generic(Fail)`. Calling
/// ReadNonVolatile does not help; the author does not understand the effect of this command.
pub enum KeystoreOperation {
    Enroll,
    SetKey { key: Key, data: Vec<u8> },
    GenerateKey { key: Key, len: u32 },
    WriteNonVolatile,
    ReadNonVolatile,
    WriteKeystore,
    ReadKeystore,
}

impl From<&KeystoreOperation> for u32 {
    fn from(operation: &KeystoreOperation) -> Self {
        use KeystoreOperation::*;
        match operation {
            Enroll => 0,
            SetKey { key: _, data: _ } => 1,
            GenerateKey { key: _, len: _ } => 2,
            WriteNonVolatile => 3,
            ReadNonVolatile => 4,
            WriteKeystore => 5,
            ReadKeystore => 6,
        }
    }
}


#[cfg(test)]
mod test {
    #[cfg(all(feature = "with-device", test))]
    use super::*;

    // #[test]
    #[cfg(all(feature = "with-device", test))]
    fn command_packet() {
        // 7 0 0 2  1 0 0 0  0 0 0 0
        insta::assert_debug_snapshot!(Command::GetProperty(Property::CurrentVersion).command_packet());
    }

    // #[test]
    #[cfg(all(feature = "with-device", test))]
    fn hid_packet() {
        // 1 0 C 0  7 0 0 2  1 0 0 0  0 0 0 0
        insta::assert_debug_snapshot!(Command::GetProperty(Property::CurrentVersion).hid_packet());
    }

}
