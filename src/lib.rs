use hidapi::HidError;

pub mod bootloader;
#[cfg(feature = "cli")]
pub mod cli;
pub mod logger;
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
