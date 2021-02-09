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
//!
//! There is also the somehow underadvertised <https://github.com/NXPmicro/spsdk>.


#[macro_use]
extern crate log;

#[macro_use(hex_str, hexstr)]
extern crate delog;

// modules
pub mod bootloader;
pub mod crypto;
pub mod protected_flash;
pub mod pki;
pub mod secure_binary;
pub mod signed_binary;
pub mod util;

// optional modules
#[cfg(feature = "http")]
pub mod http;

// re-exports
pub use bootloader::Bootloader;
pub use bootloader::Error as BootloaderError;
pub use bootloader::protocol::Error as ProtocolError;

