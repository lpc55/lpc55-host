//! Command-line interface to this crate's functionality

use clap::{self, crate_authors, crate_version, Arg, Command};

// duplicated here, because when using this `cli` module in build.rs
// to generate shell completions, there is no `lpc55` crate yet
pub const KEYSTORE_KEY_NAMES: [&str; 6] = [
    "secure-boot-kek",
    "user-key",
    "unique-device-secret",
    "prince-region-0",
    "prince-region-1",
    "prince-region-2",
];

const ABOUT: &str = "
lpc55 offers various host-side utilities.

Use -h for short descriptions and --help for more details

Project homepage: https://github.com/lpc55/lpc55-host
";
pub fn app() -> clap::Command<'static> {
    // We need to specify our version in a static because we've painted clap
    // into a corner. We've told it that every string we give it will be
    // 'static, but we need to build the version string dynamically. We can
    // fake the 'static lifetime with lazy_static.
    lazy_static::lazy_static! {
        static ref LONG_VERSION: String = long_version(None);
        // static ref LONG_VERSION: String = long_version(Some("47e1f"));
    }

    let app = Command::new("lpc55")
        .author(crate_authors!())
        .version(crate_version!())
        .long_version(LONG_VERSION.as_str())
        .about(ABOUT)
        .subcommand_required(true)
        .arg_required_else_help(true)


        .arg(Arg::new("VID")
             .long("vid")
             .help("VID of bootloader (hex)")
             .help_heading("SELECTION")
             // even without this, `cmd -v subcommand` passes -v flag to subcommand's matches
             // the difference is that now the parser allows user to `cmd subcommand -v`
             .global(true)
             .takes_value(true)
        )

        .arg(Arg::new("PID")
             .long("pid")
             .help("PID of bootloader (hex)")
             .help_heading("SELECTION")
             .global(true)
             .takes_value(true)
        )

        .arg(Arg::new("UUID")
             .long("uuid")
             .help("UUID of bootloader (hex)")
             .help_heading("SELECTION")
             .takes_value(true)
             .global(true)
        )

        .arg(Arg::new("v")
              .short('v')
              .long("verbose")
              .multiple_occurrences(true)
              .global(true)
              .help("Sets the level of verbosity (use multiple times to increase: -v = INFO, -vv = DEBUG, -vvv = TRACE)"))

        .subcommand(Command::new("http")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .visible_alias("h")
            .about("Serve http API to bootloader connector")
            .arg(Arg::new("ADDR")
                 .help("Address to bind to")
                 .long("addr")
                 .default_value("127.0.0.1")
             )
            .arg(Arg::new("PORT")
                 .help("Port to listen on")
                 .long("port")
                 .default_value("2020")
             )
        )

        .subcommand(Command::new("configure")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("configure factory and customer settings")
            .subcommand_required(true)
            .arg_required_else_help(true)

            .subcommand(Command::new("factory-settings")
                .version(crate_version!())
                .long_version(LONG_VERSION.as_str())
                .about("make changes to factory settings page (CMPA)")
                .arg(Arg::new("OUTPUT")
                     .short('o')
                     .long("output")
                     .value_name("OUTPUT")
                     .help("Output factory settings (CMPA) to a 512-byte file instead of writing to device.")
                     .required(false)
                )
                .arg(Arg::new("CONFIG")
                     .help("Configuration file containing settings")
                     .required(true)
                )
            )
            .subcommand(Command::new("customer-settings")
                .version(crate_version!())
                .long_version(LONG_VERSION.as_str())
                .about("make changes to customer settings page (CFPA)")
                .arg(Arg::new("OUTPUT")
                     .short('o')
                     .long("output")
                     .value_name("OUTPUT")
                     .help("Output customer settings (CFPA) to a 512-byte file instead of writing to device.")
                     .required(false)
                )
                .arg(Arg::new("CONFIG")
                     .help("Configuration file containing settings")
                     .required(true)
                )
                .arg(Arg::new("overwrite")
                     .help("Destructively overwrite firmware versions, PRINCE IV's, and reserved areas of customer PFR.")
                     .short('s')
                     .long("overwrite")
                     .takes_value(false)
                )
                .arg(Arg::new("dont-increment")
                     .short('a')
                     .long("dont-increment")
                     .help("Do not increment customer version number as needed to make PFR write, and use the exact version from config.")
                     .takes_value(false)
                )
            )
        )

        .subcommand(Command::new("provision")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("Run a sequence of bootloader commands defined in the config file.")
            .arg(Arg::new("CONFIG")
                    .help("Configuration file containing settings")
                    .required(true)
            )
        )

        .subcommand(Command::new("reboot")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("reboot device")
        )

        .subcommand(Command::new("keystore")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("keystore interactions")
            .subcommand_required(true)
            .arg_required_else_help(true)

            .subcommand(Command::new("enroll-puf")
                .version(crate_version!())
                .about("(re)initialize PUF, writing an activation code to the keystore")
            )

            .subcommand(Command::new("read")
                .version(crate_version!())
            )

            .subcommand(Command::new("generate-key")
                .version(crate_version!())
                .long_version(LONG_VERSION.as_str())
                .about("generate \"intrinsic\" key")
                .arg(Arg::new("KEY")
                    .help("name of key code")
                    .required(true)
                    .possible_values(&KEYSTORE_KEY_NAMES)
                )
                .arg(Arg::new("LENGTH")
                    .help("length in bytes of key to be generated") // (typical values 16 or 32)")
                    .required(true)
                    // more are possible, but let's make things easy for ourselves
                    .possible_values(&[
                        "16",
                        "32",
                    ])
                )
            )

            .subcommand(Command::new("set-key")
                .version(crate_version!())
                .long_version(LONG_VERSION.as_str())
                .about("set key")
                .arg(Arg::new("KEY")
                    .help("name of key code")
                    .required(true)
                    .possible_values(&KEYSTORE_KEY_NAMES)
                )
                .arg(Arg::new("KEYDATA_FILENAME")
                     .help("filename of file containing the raw key data bytes")
                     .required(true))
            )

            .subcommand(Command::new("write-keys")
                .version(crate_version!())
                .about("store any previously generated keys (including PUF activation codes) to non-volatile memory, i.e., PFR keystore")
            )

            .subcommand(Command::new("read-keys")
                .version(crate_version!())
                .about("ReadNonVolatile")
            )

        )

        .subcommand(Command::new("info")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .visible_alias("i")
            .about("query all properties from bootloader")
        )

        .subcommand(Command::new("ls")
            .about("list all available bootloaders")
        )

        .subcommand(Command::new("pfr")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("read out and parse PFR")
            .arg(Arg::new("FORMAT")
                 .help("Format to output the parsed PFR")
                 .long("format")
                 .default_value("json")
                 .possible_values(&[
                     "native",
                     "alt-native",
                     "json",
                     "json-pretty",
                     "raw",
                     "yaml",
                     "toml",
                 ])
            )
            .arg(Arg::new("OUTPUT FACTORY")
                    .short('f')
                    .long("output-factory")
                    .value_name("OUTPUT")
                    .help("Output the factory pfr page to a 512 byte binary file.")
                    .required(false)
            )
            .arg(Arg::new("OUTPUT CUSTOMER")
                    .short('c')
                    .long("output-customer")
                    .value_name("OUTPUT")
                    .help("Output the customer pfr pages to a 1536 byte binary file (raw, ping, and pong pages).")
                    .required(false)
            )

        )

        .subcommand(Command::new("read-memory")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .visible_aliases(&["r", "read"])
            .about("read out memory")
            .arg(Arg::new("ADDRESS")
                 .help("Address to start reading from")
                 .required(true))
            .arg(Arg::new("LENGTH")
                 .help("Number of bytes to read")
                 .required(true))
            .arg(Arg::new("OUTPUT")
                 .help("Sets the output file to use. If missing, hex-dumps to stdout.")
                 .short('o')
                 .long("output-file")
                 .takes_value(true))
        )

        .subcommand(Command::new("write-memory")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("write to memory")
            .arg(Arg::new("ADDRESS")
                 .help("Address to start writing to")
                 .required(true))
            .arg(Arg::new("INPUT")
                 .help("Sets the input file to use.")
                 .required(true)
                 .takes_value(true))
        )

        .subcommand(Command::new("write-flash")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("write to flash (like write-memory, but pads to 512 bytes and erases first)")
            .arg(Arg::new("ADDRESS")
                 .help("Address to start writing to")
                 .short('a')
                 .long("address")
                 .takes_value(true)
                 .default_value("0"))
            .arg(Arg::new("INPUT")
                 .help("Sets the input file to use.")
                 .required(true)
                 .takes_value(true))
        )

        .subcommand(Command::new("receive-sb-file")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("send SB2.1 file to target")
            .arg(Arg::new("SB-FILE")
                 .help(".sb2 file")
                 .required(true))
        )

        .subcommand(Command::new("fingerprint-certificates")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("calculate fingerprint of root certificates (aka ROTKH)")
            .arg(Arg::new("CONFIG")
                 .help("Configuration file")
                 .required(true))
        )

        .subcommand(Command::new("sign-fw")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("sign firmware")
            .arg(Arg::new("CONFIG")
                 .help("Configuration file")
                 .required(true))
            .arg(Arg::new("image")
                 .help("Input unsigned firmware. Replaces config.firmware.image entry")
                 .long("image")
                 .value_name("image")
            )
            .arg(Arg::new("signed-image")
                 .help("Output signed firmware. Replaces config.firmware.image entry")
                 .long("signed-image")
                 .value_name("signed-image")
            )
        )

        .subcommand(Command::new("assemble-sb")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("assemble SB2.1 image")
            .arg(Arg::new("CONFIG")
                 .help("Configuration file")
                 .required(true))
            .arg(Arg::new("signed-image")
                 .help("Input firmware. Replaces config.firmware.signed_image entry")
                 .long("signed-image")
                 .value_name("signed-image")
            )
            .arg(Arg::new("secure-boot-image")
                 .help("Output file. Replaces config.firmware.secure_boot_image entry")
                 .long("secure-boot-image")
                 .value_name("secure-boot-image")
            )
            .arg(Arg::new("product-version")
                 .help("Product version xx.yy.zz. Replaces config.firmware.product entry")
                 .long("product-version")
                 .value_name("product-version")
            )
            .arg(Arg::new("product-major")
                 .visible_alias("product-era")
                 .help("Product major version. Replaces config.firmware.product.major entry")
                 .long("product-major")
                 .value_name("product-major")
            )
            .arg(Arg::new("product-minor")
                 .visible_alias("product-days")
                 .help("Product minor version. Replaces config.firmware.product.minor entry")
                 .long("product-minor")
                 .value_name("product-minor")
            )
            .arg(Arg::new("product-date")
                 .help("Product date. Replaces config.firmware.product.minor entry, after converting to days since the twenties, 2020-01-01")
                 .long("product-date")
                 .value_name("product-date")
            )
        )

        .subcommand(Command::new("sb")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("firmware commands")
            .subcommand(Command::new("show")
                .version(crate_version!())
                .long_version(LONG_VERSION.as_str())
                .about("show information about file")
                .arg(Arg::new("FILE")
                     .help("file to show")
                     .required(true))
            )
        )

    ;

    app
}

/// Return the "long" format of lpc55's version string.
///
/// If a revision hash is given, then it is used. If one isn't given, then
/// the LPC55_BUILD_GIT_HASH env var is inspected for it. If that isn't set,
/// then a revision hash is not included in the version string returned.
pub fn long_version(revision_hash: Option<&str>) -> String {
    // Do we have a git hash?
    // (Yes, if ripgrep was built on a machine with `git` installed.)
    let hash = match revision_hash.or(option_env!("LPC55_BUILD_GIT_HASH")) {
        None => String::new(),
        Some(githash) => format!(" (rev {})", githash),
    };
    format!("{}{}", crate_version!(), hash)
}
