use serde::{Deserialize, Serialize};

use crate::bootloader::{
    command::{CommandTag, Version},
    Error,
    Protocol,
    Result,
};

pub struct GetProperties<'a> {
    pub protocol: &'a Protocol
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
    pub crc_check_status: crate::bootloader::Error,
    pub reserved_regions: Vec<(usize, usize)>,
    pub irq_notification_pin: IrqNotificationPin,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, enum_iterator::IntoEnumIterator, Ord, PartialEq, PartialOrd)]
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

bitflags::bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct AvailableCommands: u32 {
        const ERASE_FLASH_ALL = 1 << CommandTag::EraseFlashAll as u8;
        const ERASE_FLASH = 1 << CommandTag::EraseFlash as u8;
        const READ_MEMORY = 1 << CommandTag::ReadMemory as u8;
        const WRITE_MEMORY = 1 << CommandTag::WriteMemory as u8;
        const FILL_MEMORY = 1 << CommandTag::FillMemory as u8;
        const FLASH_SECURITY_DISABLE = 1 << CommandTag::FlashSecurityDisable as u8;
        const GET_PROPERTY = 1 << CommandTag::GetProperty as u8;
        const RECEIVE_SB_FILE = 1 << CommandTag::ReceiveSbFile as u8;
        const EXECUTE = 1 << CommandTag::Execute as u8;
        const CALL = 1 << CommandTag::Call as u8;
        const RESET = 1 << CommandTag::Reset as u8;
        const SET_PROPERTY = 1 << CommandTag::SetProperty as u8;
        const FLASH_READ_RESOURCE = 1 << CommandTag::FlashReadResource as u8;
        // TODO? it seems a lot of commands never actually show up here
        //
        // doesn't seem to turn up in the (old?) interface that lists available commands
        // const KEY_PROVISIONING = 1 << 0x15;
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
    Keystore = 0x00,
    WriteMemory = 0x01,
}

impl From<u32> for PfrKeystoreUpdateOptions {
    fn from(value: u32) -> Self {
        use PfrKeystoreUpdateOptions::*;
        match value {
            0 => Keystore,
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


impl GetProperties<'_> {
    pub fn all(&self) -> Properties {
        Properties {
            current_version: self.current_version().unwrap(),
            target_version: self.target_version().unwrap(),
            available_commands: self.available_commands().unwrap(),
            available_peripherals: self.available_peripherals().unwrap(),
            pfr_keystore_update_option: self.pfr_keystore_update_option().unwrap(),
            ram_start_address: self.ram_start_address().unwrap(),
            ram_size: self.ram_size().unwrap(),
            flash_start_address: self.flash_start_address().unwrap(),
            flash_size: self.flash_size().unwrap(),
            flash_page_size: self.flash_page_size().unwrap(),
            flash_sector_size: self.flash_sector_size().unwrap(),
            verify_writes: self.verify_writes().unwrap(),
            flash_locked: self.flash_locked().unwrap(),
            max_packet_size: self.max_packet_size().unwrap(),
            device_uuid: self.device_uuid().unwrap(),
            system_uuid: self.system_uuid().unwrap(),
            crc_check_status: self.crc_check_status().unwrap(),
            reserved_regions: self.reserved_regions().unwrap(),
            irq_notification_pin: self.irq_notification_pin().unwrap(),
        }
    }

    pub fn current_version(&self) -> Result<Version> {
        Ok(Version::from(self.protocol.property(Property::CurrentVersion)?[0]))
    }
    pub fn target_version(&self) -> Result<Version> {
        Ok(Version::from(self.protocol.property(Property::TargetVersion)?[0]))
    }
    pub fn ram_start_address(&self) -> Result<usize> {
        Ok(self.protocol.property(Property::RamStartAddress)?[0] as _)
    }
    pub fn ram_size(&self) -> Result<usize> {
        Ok(self.protocol.property(Property::RamSize)?[0] as _)
    }
    pub fn flash_start_address(&self) -> Result<usize> {
        Ok(self.protocol.property(Property::FlashStartAddress)?[0] as _)
    }
    pub fn flash_size(&self) -> Result<usize> {
        Ok(self.protocol.property(Property::FlashSize)?[0] as _)
    }
    pub fn flash_page_size(&self) -> Result<usize> {
        Ok(self.protocol.property(Property::FlashPageSize)?[0] as _)
    }
    pub fn flash_sector_size(&self) -> Result<usize> {
        Ok(self.protocol.property(Property::FlashSectorSize)?[0] as _)
    }
    pub fn max_packet_size(&self) -> Result<usize> {
        Ok(self.protocol.property(Property::MaxPacketSize)?[0] as _)
    }
    pub fn available_peripherals(&self) -> Result<AvailablePeripherals> {
        Ok(AvailablePeripherals::from_bits_truncate(self.protocol.property(Property::AvailablePeripherals)?[0]))
    }
    pub fn available_commands(&self) -> Result<AvailableCommands> {
        Ok(AvailableCommands::from_bits_truncate(self.protocol.property(Property::AvailableCommands)?[0]))
    }
    pub fn pfr_keystore_update_option(&self) -> Result<PfrKeystoreUpdateOptions> {
        let values = self.protocol.property(Property::PfrKeystoreUpdateOptions)?;
        assert_eq!(values.len(), 1);
        Ok(PfrKeystoreUpdateOptions::from(values[0]))
    }
    pub fn verify_writes(&self) -> Result<bool> {
        Ok(self.protocol.property(Property::VerifyWrites)?[0] == 1)
    }
    pub fn flash_locked(&self) -> Result<bool> {
        Ok(match self.protocol.property(Property::FlashSecurityState)?[0] {
            0x0 | 0x5AA55AA5 => false,
            0x1 | 0xC33CC33C => true,
            _ => panic!(),
        })
    }
    pub fn device_uuid(&self) -> Result<u128> {
        let values = self.protocol.property(Property::UniqueDeviceIdent)?;
        assert_eq!(values.len(), 4);
        let wrong_endian =
            ((values[3] as u128) << 96) +
            ((values[2] as u128) << 64) +
            ((values[1] as u128) << 32) +
            ((values[0] as u128))
            // ((u32::from_le_bytes(values[0].to_be_bytes()) as u128) << 96) +
            // ((u32::from_le_bytes(values[1].to_be_bytes()) as u128) << 64) +
            // ((u32::from_le_bytes(values[2].to_be_bytes()) as u128) << 32) +
            // ((u32::from_le_bytes(values[3].to_be_bytes()) as u128))
        ;
        Ok(u128::from_be_bytes(wrong_endian.to_le_bytes()))
    }
    pub fn system_uuid(&self) -> Result<u64> {
        let values = self.protocol.property(Property::SystemDeviceIdent)?;
        assert_eq!(values.len(), 2);
        Ok(((values[1] as u64) << 32) + (values[0] as u64))
    }

    pub fn crc_check_status(&self) -> Result<Error> {
        Ok(Error::from(self.protocol.property(Property::CrcCheckStatus)?[0]))
    }

    pub fn reserved_regions(&self) -> Result<Vec<(usize, usize)>> {
        let values = self.protocol.property(Property::ReservedRegions)?;
        assert_eq!(values.len() % 2, 0);
        let mut pairs = Vec::new();
        for pair in values.chunks_exact(2) {
            let left = pair[0];
            let right = pair[1];
            assert!(right >= left);
            if right > left {
                pairs.push((left as usize, right as usize));
            }
        }
        Ok(pairs)
    }

    pub fn irq_notification_pin(&self) -> Result<IrqNotificationPin> {
        Ok(IrqNotificationPin::from(self.protocol.property(Property::IrqNotificationPin)?[0]))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_available_commands() {
        assert_eq!(AvailableCommands::ERASE_FLASH_ALL.bits, (1 << 2));
    }

}
