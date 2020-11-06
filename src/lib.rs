//! Host-side library to interact with and provision NXP LPC55 devices.
//!
//! Additionally, a command-line tool `lpc55` is implemented, so far
//! it can list all properties via `lpc55 info`, and read out memory
//! (with some restrictions).
//!
//! For instance `lpc55 read-memory $((0x9DE00)) $((7*512)) -o output.bin`
//! extracts the PFR (protected flash region) of an unlocked device.
//!
//! The grand goal is to have an easily configurable `cargo` subcommand
//! which allows creating and flashing SB2.1 (secure binary) files from
//! regular ELF files, signed via a PKCS#11 backend.
//!
//! ## But why?!
//!
//! Vendor tools `blhost` and `elftosb` are semi-open source, officially
//! they are BSD-licensed, but code is only available behind a login screen.
//!
//! pyMBoot is instructive but in Python (and a bit buggy in parts).

use hidapi::HidError;

pub mod bootloader;
#[cfg(feature = "cli")]
pub mod cli;
pub mod logger;
pub mod pfr;
pub mod protocol;
pub mod status;
pub mod types;

#[derive(Debug)]
pub enum Error {
    HidApi(HidError),
    Other,
}

pub type Result<T> = std::result::Result<T, Error>;

pub use bootloader::Bootloader;
pub use status::BootloaderError;
pub use types::Properties;

impl From<HidError> for Error {
    fn from(err: HidError) -> Self {
        Self::HidApi(err)
    }
}
