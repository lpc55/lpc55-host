use core::convert::TryFrom;

use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Debug, enum_iterator::IntoEnumIterator)]
pub enum Group {
    Generic = 0,
    FlashDriver = 1,
    QuadSpiDriver = 4,
    OtfadDriver = 5,
    Bootloader = 100,
    SbLoader = 101,
    MemoryInterface = 102,
    PropertyStore = 103,
    CrcChecker = 104,
    Packetizer = 105,
    ReliableUpdate = 106,
}

impl TryFrom<u32> for Group {
    type Error = u32;
    fn try_from(group: u32) -> core::result::Result<Self, u32> {
        use Group::*;
        Ok(match group {
            0 => Generic,
            1 => FlashDriver,
            4 => QuadSpiDriver,
            5 => OtfadDriver,
            100 => Bootloader,
            101 => SbLoader,
            102 => MemoryInterface,
            103 => PropertyStore,
            104 => CrcChecker,
            105 => Packetizer,
            106 => ReliableUpdate,
            _ => return Err(group),
        })
    }
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum BootloaderError {
    Generic(GenericError),
    FlashDriver(FlashDriverError),
    PropertyStore(PropertyStoreError),
    CrcChecker(CrcCheckerError),
    Unknown(u32),
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Deserialize, enum_iterator::IntoEnumIterator, PartialEq, Serialize)]
pub enum GenericError {
    Fail = 1,
    ReadOnly = 2,
    OutOfRange = 3,
    InvalidArgument = 4,
    Timeout = 5,
    NoTransferInProgress = 6,
}

impl TryFrom<u8> for GenericError {
    type Error = u8;
    fn try_from(code: u8) -> core::result::Result<Self, u8> {
        use GenericError::*;
        Ok(match code {
            1 => Fail,
            2 => ReadOnly,
            3 => OutOfRange,
            4 => InvalidArgument,
            5 => Timeout,
            6 => NoTransferInProgress,
            _ => return Err(code),
        })
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Deserialize, enum_iterator::IntoEnumIterator, PartialEq, Serialize)]
pub enum FlashDriverError {
    Size = 0,
    Alignment = 1,
    Address = 2,
    Access = 3,
    ProtectionViolation = 4,
    CommandFailure = 5,
    UnknownProperty = 6,
    EraseKeyError = 7,
    ExecuteOnlyRegion = 8,
    UnsupportedApi = 15,
}

impl TryFrom<u8> for FlashDriverError {
    type Error = u8;
    fn try_from(code: u8) -> core::result::Result<Self, u8> {
        use FlashDriverError::*;
        Ok(match code {
            0 => Size,
            1 => Alignment,
            2 => Address,
            3 => Access,
            4 => ProtectionViolation,
            5 => CommandFailure,
            6 => UnknownProperty,
            7 => EraseKeyError,
            8 => ExecuteOnlyRegion,
            15 => UnsupportedApi,
            _ => return Err(code),
        })
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Deserialize, enum_iterator::IntoEnumIterator, PartialEq, Serialize)]
pub enum PropertyStoreError {
    UnknownProperty = 0,
    ReadOnlyProperty = 1,
    InvalidValue = 2,
}

impl TryFrom<u8> for PropertyStoreError {
    type Error = u8;
    fn try_from(code: u8) -> core::result::Result<Self, u8> {
        use PropertyStoreError::*;
        Ok(match code {
            0 => UnknownProperty,
            1 => ReadOnlyProperty,
            2 => InvalidValue,
            _ => return Err(code),
        })
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Deserialize, enum_iterator::IntoEnumIterator, PartialEq, Serialize)]
pub enum CrcCheckerError {
    Passed = 0,
    Failed = 1,
    Inactive = 2,
    Invalid = 3,
    OutOfRange = 4,
}

impl TryFrom<u8> for CrcCheckerError {
    type Error = u8;
    fn try_from(code: u8) -> core::result::Result<Self, u8> {
        use CrcCheckerError::*;
        Ok(match code {
            0 => Passed,
            1 => Failed,
            2 => Inactive,
            3 => Invalid,
            4 => OutOfRange,
            _ => return Err(code),
        })
    }
}

impl Into<(Group, u8)> for BootloaderError {
    fn into(self) -> (Group, u8) {
        use BootloaderError::*;
        match self {
            Generic(error) => (Group::Generic, error as u8),
            FlashDriver(error) => (Group::FlashDriver, error as u8),
            PropertyStore(error) => (Group::PropertyStore, error as u8),
            CrcChecker(error) => (Group::CrcChecker, error as u8),
            Unknown(_status) => panic!(),
        }
    }
}

impl From<BootloaderError> for u32 {
    fn from(error: BootloaderError) -> u32 {
        let (group, code) = error.into();
        (group as u32 * 100) + code as u32
    }
}

impl From<u32> for BootloaderError {
    fn from(status: u32) -> Self {
        use BootloaderError::*;
        if let Ok(group) = Group::try_from(status/100) {
            let code = (status % 100) as u8;
            match (group, code) {
                (Group::Generic, code) => GenericError::try_from(code).map_or(Unknown(status), Generic),
                (Group::FlashDriver, code) => FlashDriverError::try_from(code).map_or(Unknown(status), FlashDriver),
                (Group::PropertyStore, code) => PropertyStoreError::try_from(code).map_or(Unknown(status), PropertyStore),
                (Group::CrcChecker, code) => CrcCheckerError::try_from(code).map_or(Unknown(status), CrcChecker),
                _ => return Unknown(status),
            }
        } else {
            Unknown(status)
        }
    }
}
