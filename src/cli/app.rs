use clap::{self, crate_authors, crate_version, App, Arg, SubCommand};

const ABOUT: &str = "
lpc55 offers various host-side utilities.

Use -h for short descriptions and --help for more details

Project homepage: https://github.com/nickray/lpc55
";
pub fn app() -> clap::App<'static, 'static> {
    // We need to specify our version in a static because we've painted clap
    // into a corner. We've told it that every string we give it will be
    // 'static, but we need to build the version string dynamically. We can
    // fake the 'static lifetime with lazy_static.
    lazy_static::lazy_static! {
        static ref LONG_VERSION: String = long_version(None);
        // static ref LONG_VERSION: String = long_version(Some("47e1f"));
    }

    let app = App::new("lpc55")
        .author(crate_authors!())
        .version(crate_version!())
        .long_version(LONG_VERSION.as_str())
        .about(ABOUT)
        .help_message("Prints help information. Use --help for more details.")

        .arg(Arg::with_name("VID")
             .long("vid")
             // .long("verbose")
             // .short("v")
             .default_value("0x1fc9")
             .help("VID of bootloader (hex)")
             // even without this, `cmd -v subcommand` passes -v flag to subcommand's matches
             // the difference is that now the parser allows user to `cmd subcommand -v`
             .global(true)
        )

        .arg(Arg::with_name("PID")
             .long("pid")
             .default_value("0x0021")
             .help("PID of bootloader (hex)")
             // even without this, `cmd -v subcommand` passes -v flag to subcommand's matches
             // the difference is that now the parser allows user to `cmd subcommand -v`
             .global(true)
        )

        // .arg(Arg::with_name("verbose")
        //      .long("verbose")
        //      .short("v")
        //      .help("Be verbose")
        //      // even without this, `cmd -v subcommand` passes -v flag to subcommand's matches
        //      // the difference is that now the parser allows user to `cmd subcommand -v`
        //      .global(true)
        // )

        // .arg_from_usage("-d, --debug 'Print debug information'"))
        // .arg_from_usage("-v, --verbose 'Be verbose - print debug level logs'")
        .arg(Arg::with_name("v")
              .short("v")
              .long("verbose")
              .multiple(true)
              .global(true)
              .help("Sets the level of verbosity (use multiple times to increase, e.g. -vv means INFO level logs)"))

        .subcommand(SubCommand::with_name("http")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .visible_alias("h")
            .about("Serve http API to bootloader connector")
            .arg(Arg::with_name("ADDR")
                 .help("Address to bind to")
                 .long("addr")
                 .default_value("127.0.0.1")
             )
            .arg(Arg::with_name("PORT")
                 .help("Port to listen on")
                 .long("port")
                 .default_value("2020")
             )
        )

        .subcommand(SubCommand::with_name("keystore")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("keystore interactions")
            // doesn't work?
            .setting(clap::AppSettings::ArgRequiredElseHelp)

            .subcommand(SubCommand::with_name("enroll")
                .version(crate_version!())
                .about("(re)initialize PUF, writing an activation code to the keystore")
            )

            .subcommand(SubCommand::with_name("read")
                .version(crate_version!())
            )

            .subcommand(SubCommand::with_name("set-user-key")
                .version(crate_version!())
                .long_version(LONG_VERSION.as_str())
                .about("set user key")
                .arg(Arg::with_name("INDEX")
                    .help("index of key")
                    .required(true)
                    .possible_values(&[
                        "secure-boot",
                        "user",
                        "uds",
                        "prince-0",
                        "prince-1",
                        "prince-2",
                    ])
                )
                .arg(Arg::with_name("KEY_DATA_FILENAME")
                     .help("filename of file containing the raw key data bytes")
                     .required(true))
            )
        )

        .subcommand(SubCommand::with_name("info")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .visible_alias("i")
            .about("query all properties from bootloader")
        )

        .subcommand(SubCommand::with_name("pfr")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("read out and parse PFR")
            .arg(Arg::with_name("FORMAT")
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
                 ])
             )
        )

        .subcommand(SubCommand::with_name("read-memory")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .visible_aliases(&["r", "read"])
            .about("read out memory")
            .arg(Arg::with_name("ADDRESS")
                 .help("Address to start reading from")
                 .required(true))
            .arg(Arg::with_name("LENGTH")
                 .help("Number of bytes to read")
                 .required(true))
            .arg(Arg::with_name("OUTPUT_FILE")
                 .help("Sets the output file to use. If missing, hex-dumps to stdout.")
                 .short("o")
                 .long("output-file")
                 .takes_value(true))
        )

        .subcommand(SubCommand::with_name("rotkh")
            .version(crate_version!())
            .long_version(LONG_VERSION.as_str())
            .about("calculate ROTKH")
            .arg(Arg::with_name("CONFIG")
                 .help("Configuration file")
                 .required(true))
        )

        .setting(clap::AppSettings::ArgRequiredElseHelp)

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
    format!("{}{}", crate_version!(), hash,)
}


