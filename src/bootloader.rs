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
pub mod provision;
use protocol::Protocol;


pub struct Bootloader {
    pub protocol: Protocol,
    // move around; also "new" should scan the device_list iterator
    // to pull out all the info
    pub vid: u16,
    pub pid: u16,
    pub uuid: u128,
}

impl core::fmt::Debug for Bootloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootloader")
            .field("vid", &hexstr!(&self.vid.to_be_bytes()))
            .field("pid", &hexstr!(&self.pid.to_be_bytes()))
            // .field("uuid", &hexstr!(self.uuid.to_be_bytes().as_ref()))
            .field("uuid", &Uuid::from_u128(self.uuid))
        .finish()
    }
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
    ///
    /// TODO: Open question is whether this is a good idea.
    /// For instance, `write-flash` on the wrong device could wreak havoc.
    pub fn try_new(vid: Option<u16>, pid: Option<u16>) -> Option<Self> {
        Self::try_find(vid, pid, None)
        // // Bootloader is not Copy, so we can't filter
        // let mut bootloaders = Self::list();
        // let index = bootloaders.iter()
        //     .position(|bootloader| bootloader.vid == vid && bootloader.pid == pid);
        // index.map(|i| bootloaders.remove(i))
    }

    /// Attempt to find a ROM bootloader with the given UUID (and VID/PID pair).
    pub fn try_find(vid: Option<u16>, pid: Option<u16>, uuid: Option<Uuid>) -> Option<Self> {
        // Bootloader is not Copy, so we can't filter
        let mut bootloaders = Self::list();
        let index = bootloaders.iter()
            .position(|bootloader| {
                let mut predicate = true;
                if vid.is_some() && pid.is_some() {
                    predicate = bootloader.vid == vid.unwrap() && bootloader.pid == pid.unwrap();
                }
                if predicate {
                    if let Some(uuid) = uuid {
                        predicate = bootloader.uuid == uuid.as_u128();
                    }
                }
                predicate
            });
        index.map(|i| bootloaders.remove(i))
    }

    /// Returns a vector of all HID devices that appear to be ROM bootloaders
    pub fn list() -> Vec<Self> {
        let api = HidApi::new().unwrap();
        api.device_list()
            .filter_map(|device_info| {
                let vid = device_info.vendor_id();
                let pid = device_info.product_id();

                // TODO: Check if these checks are globally valid.
                // Perhaps drop them completely?
                // The intent is to avoid sending the UUID query to completely unrelated devices.
                if device_info.manufacturer_string() != Some("NXP SEMICONDUCTOR INC.") {
                    return None;
                }
                if device_info.product_string() != Some("USB COMPOSITE DEVICE") {
                    return None;
                }
                device_info.open_device(&api).ok()
                    .map(|device| (device, vid, pid))
            })
            .filter_map(|(device, vid, pid)| {
                let protocol = Protocol::new(device);
                let bootloader = GetProperties { protocol: &protocol }.device_uuid().ok()
                    .map(|uuid| Self { protocol, vid, pid, uuid });
                bootloader
            })
            .collect()
    }

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

    pub fn run_command(&self, cmd: Command) -> std::result::Result<command::Response, protocol::Error> {
        self.protocol.call(&cmd)
    }
}

#[cfg(all(feature = "with-device", test))]
fn test_all_properties() {
    // let (vid, pid) = (0x1fc9, 0x0021);
    let (vid, pid) = (0x1209, 0xb000);
    let bootloader = Bootloader::try_new(Some(vid), Some(pid)).unwrap();
    insta::assert_debug_snapshot!(bootloader.all_properties());
}
