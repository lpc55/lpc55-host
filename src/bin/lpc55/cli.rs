//! Command-line interface to this crate's functionality

use clap::{self, Args, Parser, Subcommand, ValueEnum};

#[derive(Args, Debug)]
pub struct GlobalOptions {
    #[clap(global = true, help_heading = "SELECTION", long)]
    /// USB Product ID of bootloader (hex)
    pub pid: Option<String>,

    #[clap(global = true, help_heading = "SELECTION", long)]
    /// USB Vendor ID of bootloader (hex)
    pub vid: Option<String>,

    #[clap(global = true, help_heading = "SELECTION", long)]
    /// UUID of bootloader (hex)
    pub uuid: Option<String>,

    #[clap(flatten)]
    /// Sets the level of verbosity (use multiple times to increase: -v = INFO, -vv = DEBUG, -vvv = TRACE)
    pub verbose: clap_verbosity_flag::Verbosity<clap_verbosity_flag::WarnLevel>,
}

#[derive(Parser)]
#[clap(infer_subcommands = true)]
#[clap(author, version)]
/// lpc55 offers various host-side utilities. Project homepage: <https://github.com/lpc55/lpc55-host>
pub struct Cli {
    #[clap(flatten)]
    pub global_options: GlobalOptions,
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Subcommand)]
#[clap(infer_subcommands = true)]
pub enum Subcommands {
    #[clap(subcommand)]
    Configure(Configure),
    Http(Http),
    /// Query all properties from bootloader
    Info,
    /// List all available bootloaders
    Ls,
    /// Reboot device
    Reboot,
    /// Run a sequence of bootloader commands defined in the config file.
    Provision {
        /// Configuration file containing settings
        config: String,
    },

    #[clap(subcommand)]
    Sb(Sb),

    /// Read out memory
    ReadMemory {
        /// Address to start reading from
        address: usize,
        /// Number of bytes to read
        length: usize,
        /// Sets the output file to use. If missing, hex-dumps to stdout.
        #[arg(short, long)]
        output_file: Option<String>,
    },

    /// Write to memory
    WriteMemory {
        /// Address to start writing to
        address: usize,
        /// Sets the input file to use.
        #[arg(short, long)]
        input: String,
    },

    /// Write to flash (like write-memory, but pads to 512 bytes and erases first)
    WriteFlash {
        /// Address to start writing to
        #[clap(default_value = "0", short, long)]
        address: usize,
        /// Sets the input file to use.
        input: String,
    },

    /// Send SB2.1 file to target
    ReceiveSbFile {
        /// .sb2 file
        sb_file: String,
    },

    /// Calculate fingerprint of root certificates (aka ROTKH)
    FingerprintCertificates {
        /// Configuration file
        config: String,
    },

    /// Sign a firmware image.
    SignFw {
        /// Configuration file
        config: String,
        /// Input unsigned firmware. Replaces config.firmware.image entry
        image: Option<String>,
        /// Output signed firmware. Replaces config.firmware.image entry
        signed_image: Option<String>,
    },

    /// Assemble SB2.1 image
    AssembleSb {
        /// Configuration file
        config: String,
        /// Input signed firmware. Replaces config.firmware.image entry
        #[clap(long)]
        signed_image: Option<String>,
        /// Output file. Replaces config.firmware.secure_boot_image entry
        #[clap(long)]
        secure_boot_image: Option<String>,
        /// Product version xx.yy.zz. Replaces config.firmware.product entry
        #[clap(long)]
        product_version: Option<String>,
        /// Product major version. Replaces config.firmware.product.major entry
        #[clap(visible_alias = "product-era", long)]
        product_major: Option<String>,
        /// Product minor version. Replaces config.firmware.product.minor entry
        #[clap(visible_alias = "product-days", long)]
        product_minor: Option<String>,
        /// Product date. Replaces config.firmware.product.minor entry, after converting to days since the twenties, 2020-01-01
        #[clap(long)]
        product_date: Option<String>,
    },

    /// Read out and parse PFR
    Pfr {
        /// Format to output the parsed PFR
        #[clap(default_value = "json", value_enum)]
        format: Formats,
        /// Output the customer pfr pages to a 1536 byte binary file (raw, ping, and pong pages).
        #[arg(short = 'c', long)]
        output_customer: Option<String>,
        /// Output the factory pfr page to a 512 byte binary file.
        #[arg(short = 'f', long)]
        output_factory: Option<String>,
    },

    #[clap(subcommand)]
    Keystore(Keystore),
}

/// Keystore interactions
#[derive(Subcommand)]
pub enum Keystore {
    /// (re)initialize PUF, writing an activation code to the keystore
    EnrollPuf,
    Read,
    /// generate "intrinsic" key
    GenerateKey {
        /// Name of key code
        #[clap(value_enum)]
        key: KeyName,
        /// Length in bytes of key to be generated
        /// TODO : restrict to 16 or 32
        length: u32,
    },
    SetKey {
        /// Name of key code
        #[clap(value_enum)]
        key: KeyName,
        /// Filename of file containing the raw key data bytes
        data: String,
    },
    /// Store any previously generated keys (including PUF activation codes) to non-volatile memory, i.e., PFR keystore
    WriteKeys,
    ReadKeys,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Formats {
    Native,
    AltNative,
    Json,
    JsonPretty,
    Raw,
    Yaml,
    Toml,
}

// duplicated here, because when using this `cli` module in build.rs
// to generate shell completions, there is no `lpc55` crate yet
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum KeyName {
    SecureBootKek,
    UserKey,
    UniqueDeviceSecret,
    PrinceRegion0,
    PrinceRegion1,
    PrinceRegion2,
}

#[derive(Args)]
/// Serve HTTP API to bootloader connector
pub struct Http {
    /// Address to bind to
    #[clap(default_value = "127.0.0.1", long)]
    pub addr: String,

    /// Port to listen on
    #[clap(default_value = "2020", long)]
    pub port: String,
}

#[derive(Subcommand)]
pub enum Configure {
    /// Configure factory settings page (CMPA)
    FactorySettings {
        /// Output factory settings (CMPA) to a 512-byte file instead of writing to device.
        #[arg(short, long)]
        output: Option<String>,
        /// Configuration file containing settings.
        config: String,
    },
    /// Configure customer settings page (CFPA)
    CustomerSettings {
        /// Do not increment customer version number as needed to make PFR write, and use the exact version from config.
        #[arg(short = 'a', long)]
        dont_increment: bool,
        /// Destructively overwrite firmware versions, PRINCE IV's, and reserved areas of customer PFR.
        #[arg(short = 's', long)]
        overwrite: bool,
        /// Output customer settings (CMPA) to a 512-byte file instead of writing to device.
        #[arg(short, long)]
        output: Option<String>,
        /// Configuration file containing settings.
        config: String,
    },
}

#[derive(Subcommand)]
pub enum Sb {
    /// Firmware commands
    Show {
        /// Show information about file
        file: String,
    },
}
