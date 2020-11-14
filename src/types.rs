use serde::{Deserialize, Serialize};

use crate::status::*;

pub fn to_hex_string(bytes: &[u8]) -> String {
    const HEX_CHARS_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut string = String::new();
    bytes.iter().for_each(|byte| {
        string.push(HEX_CHARS_UPPER[(byte >> 4) as usize] as char);
        string.push(HEX_CHARS_UPPER[(byte & 0xF) as usize] as char);
        string.push(' ');
    });
    string
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, enum_iterator::IntoEnumIterator, PartialEq)]
pub enum Property {
    CurrentVersion = 0x1,
    AvailablePeripherals = 0x2,
    FlashStartAddress = 0x03,
    FlashSize = 0x04,
    FlashSectorSize = 0x05,
    // FlashBlockCount = 0x06,
    AvailableCommands = 0x07,
    CrcCheckStatus = 0x08,
    // LastError = 0x09,
    VerifyWrites = 0x0A,
    MaxPacketSize = 0x0B,
    // 48
    ReservedRegions = 0x0C,
    // ValidateRegions = 0x0D,
    RamStartAddress = 0x0E,
    RamSize = 0x0F,
    // 16
    SystemDeviceIdent = 0x10,
    FlashSecurityState = 0x11,
    // 24
    UniqueDeviceIdent = 0x12,
    // FlashFacSupport = 0x13,
    // FlashAccessSegmentSize = 0x14,
    // FlashAccessSegmentCount = 0x15,
    // FlashReadMargin = 0x16,
    // QspiInitStatus = 0x17,
    TargetVersion = 0x18,

    // returns error 4: invalid argument
    // ExternalMemoryAttributes = 0x19,

    // ReliableUpdateStatus = 0x1A,
    FlashPageSize = 0x1B,
    IrqNotificationPin = 0x1C,
    PfrKeystoreUpdateOptions = 0x1D,
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

bitflags::bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct AvailablePeripherals: u32 {
        const UART = 0x01;
        const I2C = 0x02;
        const SPI = 0x04;
        const CAN = 0x08;
        const USB_HID = 0x10;
        const USB_CDC = 0x20;
        const USB_DFU = 0x40;
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum PfrKeystoreUpdateOptions {
    KeyProvisioning = 0x00,
    WriteMemory = 0x01,
}

impl From<u32> for PfrKeystoreUpdateOptions {
    fn from(value: u32) -> Self {
        use PfrKeystoreUpdateOptions::*;
        match value {
            0 => KeyProvisioning,
            1 => WriteMemory,
            _ => panic!(),
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IrqNotificationPin {
    pub pin: u8,
    pub port: u8,
    pub enabled: bool,
}

impl From<u32> for IrqNotificationPin {
    fn from(value: u32) -> Self {
        Self {
            pin: value as u8,
            port: (value >> 8) as u8,
            enabled: (value >> 31) != 0,
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
            unknown => return Err(unknown),
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

// #[derive(Copy, Clone, Debug)]
// pub struct CommandHeader {
//     tag: u8,
//     flags: u8,
//     params: u8,
// }

// impl CommandHeader {
//     pub fn to_bytes(&self) -> [u8; 4] {
//         let bytes = [0u8; 4];
//         bytes[0] =
//     }
// }

#[derive(Copy, Clone, Debug)]
pub enum Command {
    FlashEraseAll,
    FlashEraseRegion,
    ReadMemory { address: usize, length: usize },
    WriteMemory,
    FillMemory,
    FlashSecurityDisable,
    // there is actually a second parameter, Memory ID
    // 0 = internal flash
    // 1 = QSPI0 memory (unused for LPC55)
    GetProperty(Property),
    ReceiveSbFile,
    Call,
    Reset,
    FlashReadResource,
}

impl From<Command> for u8 {
    fn from(command: Command) -> u8 {
        use Command::*;
        match command {
            FlashEraseAll => 0x1,
            FlashEraseRegion => 0x2,
            ReadMemory { address: _, length: _ } => 0x3,
            WriteMemory => 0x4,
            FillMemory => 0x5,
            FlashSecurityDisable => 0x6,
            GetProperty(_) => 0x7,
            ReceiveSbFile => 0x8,
            Call => 0xA,
            Reset => 0xB,
            FlashReadResource => 0x10,
        }
    }
}

bitflags::bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct AvailableCommands: u32 {
        const FLASH_ERASE_ALL = 1 << 0x1;
        const FLASH_ERASE_REGION = 1 << 0x2;
        const READ_MEMORY = 1 << 0x3;
        const WRITE_MEMORY = 1 << 0x4;
        const FILL_MEMORY = 1 << 0x5;
        const FLASH_SECURITY_DISABLE = 1 << 0x6;
        const GET_PROPERTY = 1 << 0x7;
        const RECEIVE_SB_FILE = 1 << 0x8;
        const CALL = 1 << 0xA;
        const RESET = 1 << 0xB;
        const FLASH_READ_RESOURCE = 1 << 0x10;
    }
}

impl Command {
    pub fn hid_packet(&self) -> Vec<u8> {
        let command_packet = self.command_packet();
        // dbg!(to_hex_string(&command_packet.clone()));

        let mut header = [0u8; 4];
        // pyMBoot does: `pack('<2BH', report_id, 0x00, data_len)`
        // MCU Bootloader 2.5.0 RM rev 1. (05/2018) says: 1 byte report ID, 2 bytes packet length
        // It seems pyMBoot is right, and the RM is wrong
        header[..2].copy_from_slice(&(ReportId::CommandOut as u8 as u16).to_le_bytes());
        header[2..].copy_from_slice(&(command_packet.len() as u16).to_le_bytes());

        // umm...
        let mut hid_packet = Vec::new();
        hid_packet.extend_from_slice(&header);
        hid_packet.extend_from_slice(&command_packet);
        hid_packet
    }

    fn construct_packet(&self, data_phase: bool, params: &[u32]) -> Vec<u8> {
        assert!(params.len() <= 7);

        let header = [
            // command tag
            {
                let command = *self;
                let tag = u8::from(command);
                tag
            },
            // data phase flag
            data_phase as u8,
            // reserved
            0,
            // number of parameters
            params.len() as u8,
        ];

        let mut packet = Vec::new();

        packet.extend_from_slice(&header);
        params.iter().for_each(|param| { /*dbg!(param);*/ packet.extend_from_slice(param.to_le_bytes().as_ref()) } );
        assert_eq!(packet.len(), 4*(1 + params.len()));

        packet.resize(32, 0);
        packet
    }

    pub fn command_packet(&self) -> Vec<u8> {
        let command = *self;
        use Command::*;
        match command {
            GetProperty(property) => {
                // dbg!(property as u8);
                self.construct_packet(false, [property as u8 as u32, 0].as_ref())
            }
            ReadMemory { address, length } => {
                // PyMBOOT is kinda bugged here, it signals sending 3 parameters
                // (but the third one is set to zero)
                self.construct_packet(false, [address as u32, length as u32].as_ref())
            }
            _ => todo!()
        }
    }
}

#[repr(u8)]
#[derive(Clone, Debug, enum_iterator::IntoEnumIterator)]
pub enum Response {
    Generic = 0xA0,
    GetProperty = 0xA7,
    ReadMemory = 0xA3,
    FlashReadOnce = 0xAF,
    FlashReadResource = 0xB0,
}

// pub struct Report {
//     report_id: ReportId,
//     data: Vec<u8>,
//     offset: usize,
// }

// impl Report {
//     pub fn new(report_id: ReportId, data: Vec<u8>) -> Self {
//         Self { report_id, data, offset: 0 }
//     }

//     // pub fn encode(&self) -> Vec<u8> {

//     // }
// }

#[repr(u8)]
#[derive(Clone, Debug, enum_iterator::IntoEnumIterator)]
pub enum ReportId {
    CommandOut = 0x1,
    CommandIn = 0x3,
    DataOut = 0x2,
    DataIn = 0x4,
}


#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Properties {
    pub current_version: Version,
    pub target_version: Version,
    pub available_commands: AvailableCommands,
    pub available_peripherals: AvailablePeripherals,
    pub pfr_keystore_update_option: PfrKeystoreUpdateOptions,
    pub ram_start_address: usize,
    pub ram_size: usize,
    pub flash_start_address: usize,
    pub flash_size: usize,
    pub flash_page_size: usize,
    pub flash_sector_size: usize,
    pub verify_writes: bool,
    pub flash_locked:bool,
    pub max_packet_size: usize,
    pub device_uuid: u128,
    pub system_uuid: u64,
    pub crc_check_status: BootloaderError,
    pub reserved_regions: Vec<(usize, usize)>,
    pub irq_notification_pin: IrqNotificationPin,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn command_packet() {
        // 7 0 0 2  1 0 0 0  0 0 0 0
        insta::assert_debug_snapshot!(Command::GetProperty(Property::CurrentVersion).command_packet());
    }

    #[test]
    fn hid_packet() {
        // 1 0 C 0  7 0 0 2  1 0 0 0  0 0 0 0
        insta::assert_debug_snapshot!(Command::GetProperty(Property::CurrentVersion).hid_packet());
    }
}
