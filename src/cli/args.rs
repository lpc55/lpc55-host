use std::env;
use std::error;
use std::io::{self, Write};
use std::process;
use std::sync::Arc;

use clap;

use crate::cli::app;
use crate::logger::Logger;

/// The command that lpc55 should execute based on the command line
/// configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Info,
    MemoryList,
}

/// The primary configuration object used throughout lpc55. It provides a
/// high-level convenient interface to the provided command line arguments.
///
/// An `Args` object is cheap to clone and can be used from multiple threads
/// simultaneously.
#[derive(Clone, Debug)]
pub struct Args(pub Arc<ArgsImp>);

#[derive(Clone, Debug)]
pub struct ArgsImp {
    /// Mid-to-low level routines for extracting CLI arguments.
    matches: ArgMatches,
}

/// `ArgMatches` wraps `clap::ArgMatches` and provides semantic meaning to
/// the parsed arguments.
#[derive(Clone, Debug)]
pub struct ArgMatches(pub clap::ArgMatches<'static>);

impl ArgMatches {
    /// Create an ArgMatches from clap's parse result.
    fn new(clap_matches: clap::ArgMatches<'static>) -> ArgMatches {
        ArgMatches(clap_matches)
    }

    fn to_args(self) -> Result<Args> {
        Ok(Args(Arc::new(ArgsImp {
            matches: self,
        })))
    }

    pub fn command(&self) -> Option<Command> {
        // You can handle information about subcommands by requesting their matches by name
        // (as below), requesting just the name used, or both at the same time
        if let Some(_matches) = self.0.subcommand_matches("info") {
            // if matches.is_present("debug") {
            //     println!("Printing debug info...");
            // } else {
            //     println!("Printing normally...");
            // }
            return Some(Command::Info);
        }
        None
    }
}

pub type Result<T> = ::std::result::Result<T, Box<dyn error::Error>>;

impl Args {
    /// Parse the command line arguments for this process.
    ///
    /// If a CLI usage error occurred, then exit the process and print a usage
    /// or error message. Similarly, if the user requested the version of
    /// ripgrep, then print the version and exit.
    ///
    /// Also, initialize a global logger.
    pub fn parse() -> Result<Args> {
        // We parse the args given on CLI. This does not include args from
        // the config. We use the CLI args as an initial configuration while
        // trying to parse config files. If a config file exists and has
        // arguments, then we re-parse argv, otherwise we just use the matches
        // we have here.
        let early_matches = ArgMatches::new(clap_matches(env::args_os())?);

        if let Err(err) = Logger::init() {
            return Err(format!("failed to initialize logger: {}", err).into());
        }

        // if early_matches.is_present("trace") {
        //     log::set_max_level(log::LevelFilter::Trace);
        // } else if early_matches.is_present("debug") {
        //     log::set_max_level(log::LevelFilter::Debug);
        // } else {
        //     log::set_max_level(log::LevelFilter::Warn);
        // }

        // (...)
        early_matches.to_args()
    }

    pub fn matches(&self) -> &ArgMatches {
        &self.0.matches
    }

    pub fn command(&self) -> Option<Command> {
        self.matches().command()
    }

}

/// Returns a clap matches object if the given arguments parse successfully.
///
/// Otherwise, if an error occurred, then it is returned unless the error
/// corresponds to a `--help` or `--version` request. In which case, the
/// corresponding output is printed and the current process is exited
/// successfully.
fn clap_matches<I, T>(args: I) -> Result<clap::ArgMatches<'static>>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let err = match app::app().get_matches_from_safe(args) {
        Ok(matches) => return Ok(matches),
        Err(err) => err,
    };
    if err.use_stderr() {
        return Err(err.into());
    }
    // Explicitly ignore any error returned by write!. The most likely error
    // at this point is a broken pipe error, in which case, we want to ignore
    // it and exit quietly.
    //
    // (This is the point of this helper function. clap's functionality for
    // doing this will panic on a broken pipe error.)
    let _ = write!(io::stdout(), "{}", err);
    process::exit(0);
}

