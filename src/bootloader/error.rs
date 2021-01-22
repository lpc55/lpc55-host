//! https://github.com/NXPmicro/spsdk/blob/020a983e53769fe16cb9b49395d56f0201eccca6/spsdk/mboot/error_codes.py

use core::convert::TryFrom;

use serde::{Deserialize, Serialize};

// todo: fix
use super::Error as BootloaderError;

#[repr(u8)]
#[derive(Clone, Debug, enum_iterator::IntoEnumIterator)]
pub enum ErrorGroup {
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

impl TryFrom<u32> for ErrorGroup {
    type Error = u32;
    fn try_from(group: u32) -> core::result::Result<Self, u32> {
        use ErrorGroup::*;
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

macro_rules! generate {
    ($Error:ident: $($error:ident = $code:literal,)*) => {

        #[repr(u8)]
        #[derive(Copy, Clone, Debug, Deserialize, enum_iterator::IntoEnumIterator, PartialEq, Serialize)]
        pub enum $Error { $(
            $error = $code,
        )* }

        impl TryFrom<u8> for $Error {
            type Error = u8;
            fn try_from(code: u8) -> core::result::Result<Self, u8> {
                use $Error::*;
                Ok(match code { $(
                    $code => $error,
                )*
                    _ => return Err(code),
                })
            }
        }
    }
}

generate! { GenericError:
    Fail = 1,
    ReadOnly = 2,
    OutOfRange = 3,
    InvalidArgument = 4,
    Timeout = 5,
    NoTransferInProgress = 6,
}

generate! { FlashDriverError:
    Size = 0,
    Alignment = 1,
    Address = 2,
    Access = 3,
    ProtectionViolation = 4,
    CommandFailure = 5,
    UnknownProperty = 6,
    EraseKeyError = 7,
    ExecuteOnlyRegion = 8,
    CommandNotSupported = 15,
    InfieldScratchVersionBehindActualInfieldVersion = 32,
}

generate! { SbLoaderError:
    SectionOverrun = 0,
    Signature = 1,
    SectionLength = 2,
    UnencryptedOnly = 3,
    EofReached = 4,
    Checksum = 5,
    Crc32Error = 6,
    UnknownCommand = 7,
    IdNotFound = 8,
    DataUnderrun = 9,
    JumpReturned = 10,
    CallFailed = 11,
    KeyNotFound = 12,
    SecureOnly = 13,
    ResetReturned = 14,
    RollbackBlocked = 15,
    InvalidSectionMacCount = 16,
    UnexpectedCommand = 17,
}

generate! { PropertyStoreError:
    UnknownProperty = 0,
    ReadOnlyProperty = 1,
    InvalidValue = 2,
}

generate! { CrcCheckerError:
    Passed = 0,
    Failed = 1,
    Inactive = 2,
    Invalid = 3,
    OutOfRange = 4,
}

impl Into<(ErrorGroup, u8)> for BootloaderError {
    fn into(self) -> (ErrorGroup, u8) {
        use BootloaderError::*;
        match self {
            Generic(error) => (ErrorGroup::Generic, error as u8),
            FlashDriver(error) => (ErrorGroup::FlashDriver, error as u8),
            PropertyStore(error) => (ErrorGroup::PropertyStore, error as u8),
            CrcChecker(error) => (ErrorGroup::CrcChecker, error as u8),
            SbLoader(error) => (ErrorGroup::SbLoader, error as u8),
            Unknown(_status) => panic!(),
        }
    }
}

impl From<BootloaderError> for u32 {
    fn from(error: BootloaderError) -> u32 {
        let (group, code) = error.into();
        let status = (group as u32 * 100) + code as u32;
        status
    }
}

impl From<u32> for BootloaderError {
    fn from(status: u32) -> Self {
        use BootloaderError::*;
        if let Ok(group) = ErrorGroup::try_from(status/100) {
            let code = (status % 100) as u8;
            match (group, code) {
                (ErrorGroup::Generic, code) => GenericError::try_from(code).map_or(Unknown(status), Generic),
                (ErrorGroup::FlashDriver, code) => FlashDriverError::try_from(code).map_or(Unknown(status), FlashDriver),
                (ErrorGroup::PropertyStore, code) => PropertyStoreError::try_from(code).map_or(Unknown(status), PropertyStore),
                (ErrorGroup::CrcChecker, code) => CrcCheckerError::try_from(code).map_or(Unknown(status), CrcChecker),
                (ErrorGroup::SbLoader, code) => SbLoaderError::try_from(code).map_or(Unknown(status), SbLoader),
                _ => return Unknown(status),
            }
        } else {
            Unknown(status)
        }
    }
}
