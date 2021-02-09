//! The bootloader interface
//!
//! Construct a `Bootloader` from a VID/PID pair (optionally a UUID to disambiguate),
//! then call its methods.

use enum_iterator::IntoEnumIterator;
use hidapi::HidApi;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod command;
pub use command::{Command, KeystoreOperation, Response};
pub mod error;
pub mod property;
pub use property::{GetProperties, Property, Properties};
pub mod protocol;
use protocol::Protocol;


#[derive(Debug)]
pub struct Bootloader {
    pub protocol: Protocol,
    // move around; also "new" should scan the device_list iterator
    // to pull out all the info
    pub vid: u16,
    pub pid: u16,
    pub uuid: u128,
}

/// Bootloader commands return a "status". The non-zero statii can be split
/// as `100*group + code`. We map these groups into enum variants, containing
/// the code interpreted as an error the area.
///
/// TODO: To implement StdError via thiserror::Error, we need to
/// add error messages to all the error variants.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Error {
    Generic(error::GenericError),
    FlashDriver(error::FlashDriverError),
    PropertyStore(error::PropertyStoreError),
    CrcChecker(error::CrcCheckerError),
    SbLoader(error::SbLoaderError),
    Unknown(u32),
}

pub type Result<T> = std::result::Result<T, Error>;


impl Bootloader {
    /// Select first available ROM bootloader with the given VID/PID pair.
    pub fn try_new(vid: u16, pid: u16) -> anyhow::Result<Self> {
        let api = HidApi::new()?;
        let device = api.open(vid, pid)?;
        let protocol = Protocol::new(device);
        let uuid = GetProperties { protocol: &protocol }.device_uuid().unwrap();
        Ok(Self { protocol, vid, pid, uuid })

    }

    /// Attempt to find a ROM bootloader with the given UUID (and VID/PID pair).
    pub fn try_find(vid: u16, pid: u16, uuid: Option<Uuid>) -> anyhow::Result<Self> {
        if let Some(uuid) = uuid {
            println!("UUID v{:?} variant {:?}", &uuid.get_version(), &uuid.get_variant());
            let api = HidApi::new()?;
            for device_info in api.device_list() {
                if (vid, pid) != (device_info.vendor_id(), device_info.product_id()) {
                    continue;
                }
                let device = device_info.open_device(&api)?;
                let protocol = Protocol::new(device);
                let device_uuid = GetProperties { protocol: &protocol }.device_uuid().unwrap();
                if uuid.as_u128() == device_uuid {
                    return Ok(Self { protocol, vid, pid, uuid: device_uuid });
                }
            }
            Err(anyhow::anyhow!("No device with VID:PID = {:04X}:{:04X} and UUID {:X} found", vid, pid, uuid))
        } else {
            Self::try_new(vid, pid)
        }
    }

    // pub fn command(&self, command: Command) {
    // }

    pub fn info(&self) {
        for property in Property::into_enum_iter() {
            // println!("\n{:?}", property);
            self.property(property).ok();
        }
    }

    pub fn reboot(&self) {
        info!("calling Command::Reset");
        self.protocol.call(&Command::Reset).expect("success");
    }

    pub fn enroll_puf(&self) {
        // first time i ran this:
        // 03000C00 A0000002 00000000 15000000 00000000 00000000 00000000 00000000 00000000 00000030 FF5F0030 00000020 FF5F0020 00000000 00000000
        // second time i ran this:
        // 03000C00 A0000002 00000000 15000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        self.protocol.call(&Command::Keystore(KeystoreOperation::Enroll)).expect("success");
        info!("PUF enrolled");
    }

    /// The reason for this wrapper is that the device aborts early if more than 512 bytes are
    /// requested. Unclear why it does this...
    ///
    /// This is a traffic trace (requesting all of PFR in one go), removing the "surplus junk"
    ///
    /// --> 01002000 03000002 00DE0900 000E0000 00000000 00000000 00000000 00000000 00000000
    /// <-- 03000C00 A3010002 00000000 000E0000
    /// <-- 04003800 00000000 02000000 02000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 02000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    /// <-- 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 ECE6A668 2922E9CC F462A95F DF81E180 E1528642 7C520098
    /// <-- 04000000
    /// <-- 03000C00 A0000002 65000000 03000000
    ///
    /// The error is 101 = 100 + 1 = (supposedly) a flash driver "alignment" error (?!)
    ///
    /// The interesting thing is that at the point where the device aborts, there are 8 bytes
    /// remaining, which it otherwise produces in a final
    ///
    /// <-- 04000800 2C80BA51 B067AF3C
    /// <-- 03000C00 A0000002 00000000 03000000
    ///
    /// TODO: should we just enter our desired length anyway, and handle such situations?
    /// As in retry at the new index, with the reduced length? Instead of using a fixed 512B chunking?
    ///
    /// TODO: Need to expect errors such as: `Response status = 139 (0x8b) kStatus_FLASH_NmpaUpdateNotAllowed`
    /// This happens with `read-memory $((0x0009_FC70)) 16`, which would be the UUID
    ///
    /// TODO: Need to expect errors such as: `Response status = 10200 (0x27d8) kStatusMemoryRangeInvalid`
    /// This happens with `read-memory $((0x5000_0FFC)) 1`, which would be the DIEID (for chip rev)
    pub fn read_memory(&self, address: usize, length: usize) -> Vec<u8> {
        let mut data = Vec::new();
        let mut remaining = length;
        let mut address = address;
        while remaining > 0 {
            let length = core::cmp::min(remaining, 512);
            data.extend_from_slice(&self.read_memory_at_most_512(address, length));
            remaining -= length;
            address += length;
        }
        data
    }

    pub fn read_memory_at_most_512(&self, address: usize, length: usize) -> Vec<u8> {
        let response = self.protocol.call(&Command::ReadMemory { address, length }).expect("success");
        if let Response::ReadMemory(data) = response {
            data
        } else {
            todo!();
        }
    }

    pub fn receive_sb_file(&self, data: Vec<u8>) {
        let _response = self.protocol.call(&Command::ReceiveSbFile { data }).expect("success");
    }

    pub fn erase_flash(&self, address: usize, length: usize) {
        let _response = self.protocol.call(&Command::EraseFlash { address, length }).expect("success");
    }

    pub fn write_memory(&self, address: usize, data: Vec<u8>) {
        let _response = self.protocol.call(&Command::WriteMemory { address, data }).expect("success");
    }

    fn property(&self, property: property::Property) -> Result<Vec<u32>> {
        self.protocol.property(property)
    }

    pub fn properties(&self) -> property::GetProperties<'_> {
        GetProperties { protocol: &self.protocol }
    }

    pub fn all_properties(&self) -> Properties {
        self.properties().all()
    }
}

#[cfg(test)]
#[test]
fn test_all_properties() {
    // let (vid, pid) = (0x1fc9, 0x0021);
    let (vid, pid) = (0x1209, 0xb000);
    let bootloader = Bootloader::try_new(vid, pid).unwrap();
    insta::assert_debug_snapshot!(bootloader.all_properties());
}
