///
/// A "porcelain" layer for working with lpc55 bootloaders designed for custom provisioning.
///
use std::convert::TryFrom;
use std::fs;

use serde::{Deserialize, Serialize};

use super::command::Command;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Commands for the bootloader
    pub provisions: Vec<Command>,
}

impl TryFrom<&'_ str> for Config {
    type Error = anyhow::Error;
    fn try_from(config_filename: &str) -> anyhow::Result<Self> {
        let config = fs::read_to_string(config_filename)?;
        let config: Config = toml::from_str(&config)?;
        trace!("{:#?}", &config);
        Ok(config)
    }
}
