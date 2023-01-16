//! Binary implementing the CLI in `cli.rs`

use core::convert::TryFrom;
use std::fs;
use std::io::{self, Write as _};

use anyhow::{anyhow, Context as _};
use delog::hex_str;
use log::{info, trace, warn};
use uuid::Uuid;

use lpc55::bootloader::{command, Bootloader, UuidSelectable as _};

mod cli;
mod logger;

// implemented here, because we can't do it in cli.rs or command.rs
use lpc55::bootloader::command::Key;
impl From<cli::KeyName> for Key {
    fn from(key: cli::KeyName) -> Key {
        use cli::KeyName::*;
        match key {
            SecureBootKek => Key::SecureBootKek,
            UserKey => Key::UserPsk,
            UniqueDeviceSecret => Key::UniqueDeviceSecret,
            PrinceRegion0 => Key::PrinceRegion0,
            PrinceRegion1 => Key::PrinceRegion1,
            PrinceRegion2 => Key::PrinceRegion2,
        }
    }
}

fn main() {
    use clap::Parser;
    let args = cli::Cli::parse();

    if let Err(err) = try_main(args) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}

fn check_align(number: usize) -> anyhow::Result<()> {
    if number % 512 == 0 {
        Ok(())
    } else {
        Err(anyhow!("{} is not a multiple of 512", number))
    }
}

fn try_main(args: cli::Cli) -> anyhow::Result<()> {
    logger::Logger::init().unwrap();

    log::set_max_level(args.global_options.verbose.log_level_filter());
    // match args.occurrences_of("v") {
    //     // 0 => log::set_max_level(log::LevelFilter::Error),
    //     0 => log::set_max_level(log::LevelFilter::Warn),
    //     1 => log::set_max_level(log::LevelFilter::Info),
    //     2 => log::set_max_level(log::LevelFilter::Debug),
    //     _ => log::set_max_level(log::LevelFilter::Trace),
    // };

    let pid = match args.global_options.pid {
        Some(pid) => Some(
            u16::from_str_radix(pid.trim_start_matches("0x"), 16)
                .map_err(|_| anyhow!("Could not parse PID"))?,
        ),
        _ => None,
    };

    let vid = match args.global_options.vid {
        Some(vid) => Some(
            u16::from_str_radix(vid.trim_start_matches("0x"), 16)
                .map_err(|_| anyhow!("Could not parse VID"))?,
        ),
        _ => None,
    };

    let uuid = args
        .global_options
        .uuid
        .map(|string| Uuid::parse_str(string.as_str()))
        .transpose()?;

    let bootloader =
        || Bootloader::try_find(vid, pid, uuid).context("Could not attach to a bootloader");

    use cli::Subcommands;
    match args.subcommand {
        Subcommands::Http(command) => {
            let bootloader = bootloader()?;
            let addr = command.addr;
            let port = command.port.parse::<u16>().unwrap();
            let http_config = lpc55::http::HttpConfig {
                addr,
                port,
                timeout_ms: 5000,
            };
            let server = lpc55::http::Server::new(&http_config, bootloader)?;
            server.run()?;
            return Ok(());
        }

        Subcommands::Ls => {
            let bootloaders = Bootloader::list();
            println!("bootloaders:");
            for bootloader in bootloaders {
                println!("{:?}", &bootloader);
            }
        }

        Subcommands::Info => {
            let bootloader = bootloader()?;
            bootloader.info();
            println!("{:#?}", bootloader.all_properties());
            return Ok(());
        }

        Subcommands::Reboot => {
            let bootloader = bootloader()?;
            bootloader.reboot();
        }

        Subcommands::Configure(subcommand) => {
            use cli::Configure;
            match subcommand {
                Configure::CustomerSettings {
                    config,
                    dont_increment,
                    output,
                    overwrite,
                } => {
                    let config_path = std::path::Path::new(&config);
                    let settings = fs::read_to_string(config_path)?;
                    let wrapped_settings: lpc55::protected_flash::WrappedCustomerSettings =
                        match config_path.extension() {
                            Some(extension) => match extension {
                                os_str if os_str == "yaml" => serde_yaml::from_str(&settings)?,
                                os_str if os_str == "toml" => toml::from_str(&settings)?,
                                extension => todo!("extension {:?} not implemented", extension),
                            },
                            None => {
                                return Err(anyhow::anyhow!(
                                    "no extension detected in path {:?}",
                                    &config_path
                                ))
                            }
                        };

                    let mut settings = wrapped_settings.customer_settings;
                    info!("settings: {:#?}", &wrapped_settings.customer_settings);

                    match output {
                        None => {
                            let bootloader = bootloader()?;

                            let current_pfr_raw = bootloader.read_memory(0x9_DE00, 512 * 7);
                            let current_pfr = lpc55::protected_flash::ProtectedFlash::try_from(
                                &current_pfr_raw[..],
                            )
                            .unwrap();
                            let latest_pfr = current_pfr.customer.most_recent();

                            if !dont_increment {
                                if settings.customer_version.read() != 0 {
                                    warn!(
                                        "Ignoring customer version {} from settings file.",
                                        settings.customer_version.read()
                                    );
                                }

                                info!("auto incrementing");
                                settings.customer_version = latest_pfr.customer_version;
                                settings.customer_version.increment();
                            }

                            let mut settings = Vec::from(settings.to_bytes()?.as_ref());

                            if !overwrite {
                                info!("preserving firmware, prince-iv, and reserved fields.");

                                // Do not overwrite firmware versions
                                let protect = 8..16;
                                settings[protect.clone()]
                                    .clone_from_slice(&current_pfr_raw[protect]);
                                // Do not overwrite any of the PRINCE IV's or reserved areas.
                                let protect = 48..256;
                                settings[protect.clone()]
                                    .clone_from_slice(&current_pfr_raw[protect]);
                            }

                            trace!("writing pfr: {}", hex_str!(&settings));

                            bootloader.write_memory(
                                lpc55::protected_flash::CUSTOMER_SETTINGS_SCRATCH_ADDRESS,
                                settings,
                            );
                        }

                        Some(output_name) => {
                            fs::write(&output_name, Vec::from(settings.to_bytes()?.as_ref()))
                                .expect("Unable to write file");
                            println!("outputing to {}", output_name);
                        }
                    }
                }
                Configure::FactorySettings { config, output } => {
                    // TODO: https://github.com/NXPmicro/spsdk/blob/020a983e53769fe16cb9b49395d56f0201eccca6/spsdk/data/pfr/rules.json#L51-L61
                    //
                    // - ensure DICE key calc is disabled
                    // - if secure-boot is on, at least one of RoT keys must be enabled
                    let config_path = std::path::Path::new(&config);
                    let settings = fs::read_to_string(config_path)?;
                    let mut wrapped_settings: lpc55::protected_flash::WrappedFactorySettings =
                        match config_path.extension() {
                            Some(extension) => match extension {
                                os_str if os_str == "yaml" => serde_yaml::from_str(&settings)?,
                                os_str if os_str == "toml" => toml::from_str(&settings)?,
                                extension => todo!("extension {:?} not implemented", extension),
                            },
                            None => {
                                return Err(anyhow::anyhow!(
                                    "no extension detected in path {:?}",
                                    &config_path
                                ))
                            }
                        };

                    info!("settings: {:#?}", &wrapped_settings.factory_settings);

                    let settings =
                        Vec::from(wrapped_settings.factory_settings.to_bytes()?.as_ref());

                    trace!("binary settings:\n{}", hex_str!(&settings, 4, sep: "\n"));

                    match output {
                        None => {
                            let bootloader = bootloader()?;
                            bootloader.write_memory(
                                lpc55::protected_flash::FACTORY_SETTINGS_ADDRESS,
                                settings,
                            );
                        }
                        Some(output_name) => {
                            fs::write(&output_name, &settings).expect("Unable to write file");
                            println!("outputing to {}", output_name);
                        }
                    }
                }
            }
        }

        Subcommands::Keystore(subcommand) => {
            use cli::Keystore::*;
            match subcommand {
                EnrollPuf => {
                    let bootloader = bootloader()?;
                    bootloader.enroll_puf();
                    return Ok(());
                }

                Read => {
                    let bootloader = bootloader()?;
                    // let data = bootloader.read_memory(0x9_DE60, 3*512);

                    let command =
                        command::Command::Keystore(command::KeystoreOperation::ReadKeystore);
                    let response = bootloader.protocol.call(&command).expect("success");

                    let data = if let command::Response::Data(data) = response {
                        data
                    } else {
                        todo!();
                    };
                    dbg!(&data);

                    let keystore =
                        lpc55::protected_flash::Keystore::try_from(data.as_slice()).unwrap();
                    println!("{}", serde_json::to_string(&keystore).unwrap());
                    return Ok(());
                }

                GenerateKey { key, length } => {
                    let bootloader = bootloader()?;
                    let key: Key = key.into();

                    let command =
                        command::Command::Keystore(command::KeystoreOperation::GenerateKey {
                            key,
                            len: length,
                        });

                    bootloader.protocol.call(&command).expect("success");
                    return Ok(());
                }

                SetKey { key, data } => {
                    let bootloader = bootloader()?;
                    let key: Key = key.into();
                    let data = fs::read(&*data)?;

                    let command = command::Command::Keystore(command::KeystoreOperation::SetKey {
                        key,
                        data,
                    });

                    bootloader.protocol.call(&command).expect("success");
                    return Ok(());
                }

                WriteKeys => {
                    let bootloader = bootloader()?;

                    let command =
                        command::Command::Keystore(command::KeystoreOperation::WriteNonVolatile);

                    bootloader.protocol.call(&command).expect("success");
                    return Ok(());
                }

                ReadKeys => {
                    let bootloader = bootloader()?;

                    let command =
                        command::Command::Keystore(command::KeystoreOperation::ReadNonVolatile);

                    bootloader.protocol.call(&command).expect("success");
                    return Ok(());
                }
            }
        }

        Subcommands::Pfr {
            format,
            output_customer,
            output_factory,
        } => {
            let bootloader = bootloader()?;
            let data = bootloader.read_memory(0x9_DE00, 7 * 512);
            // let empty = data.iter().all(|&byte| byte == 0);
            // if empty {
            //     println!("PFR region is completely zeroed out");
            // } else {
            //     println!("PFR region is not completely zeroed out");
            // }
            let pfr = lpc55::protected_flash::ProtectedFlash::try_from(&data[..]).unwrap();
            // println!("PFR = {:#?}", &pfr);
            // println!("PFR = {:?}", &pfr);

            use cli::Formats::*;
            match format {
                AltNative => println!("{:#?}", &pfr),
                Native => println!("{:?}", &pfr),
                Json => println!("{}", serde_json::to_string(&pfr).unwrap()),
                JsonPretty => println!("{}", serde_json::to_string_pretty(&pfr).unwrap()),
                Raw => {
                    if atty::is(atty::Stream::Stdout) {
                        panic!("don't dump binary data to terminal");
                    } else {
                        io::stdout().write_all(&data).unwrap()
                    }
                }
                Toml => println!("{}", toml::Value::try_from(pfr).unwrap()),
                Yaml => println!("{}", serde_yaml::to_string(&pfr).unwrap()),
                // "yaml-pretty" => println!("{}", serde_yaml::to_string_pretty(&pfr).unwrap()),
                // _ => panic!(),
            }
            if let Some(filename) = output_factory {
                fs::write(filename, &data[512 * 3..512 * 4]).expect("Unable to write file");
            }

            if let Some(filename) = output_customer {
                fs::write(filename, &data[0..512 * 3]).expect("Unable to write file");
            }
        }

        Subcommands::WriteMemory { address, input } => {
            let bootloader = bootloader()?;
            check_align(address)?;
            let data = fs::read(input).unwrap();
            check_align(data.len())?;
            bootloader.write_memory(address, data);
            return Ok(());
        }

        Subcommands::WriteFlash { address, input } => {
            let bootloader = bootloader()?;
            check_align(address)?;
            let mut data = fs::read(input)?;
            let length = data.len();
            let overshoot = length % 512;
            if overshoot > 0 {
                data.resize(length + (512 - overshoot), 0);
            }
            bootloader.erase_flash(address, data.len());
            bootloader.write_memory(address, data);
            return Ok(());
        }

        Subcommands::ReadMemory {
            address,
            length,
            output_file,
        } => {
            let bootloader = bootloader()?;
            // let data = bootloader.read_memory_at_most_512(address, length);
            let data = bootloader.read_memory(address, length);

            if let Some(output_filename) = output_file {
                let mut file = fs::File::create(output_filename)?;
                use std::io::Write;
                file.write_all(&data)?;
                file.sync_all()?;
            } else {
                // lpc55::print_hex(data, 16);
                println!("{}", hex_str!(&data, 16));
            }
            return Ok(());
        }

        Subcommands::ReceiveSbFile { sb_file } => {
            let bootloader = bootloader()?;
            let image = fs::read(sb_file)?;
            let bar = indicatif::ProgressBar::new(image.len() as u64);
            let progress = |bytes: usize| bar.set_position(bytes as u64);
            bootloader.receive_sb_file(&image, Some(&progress));
            return Ok(());
        }

        Subcommands::Provision { config } => {
            let config = lpc55::bootloader::provision::Config::try_from(config.as_str())?;

            let bootloader = bootloader()?;
            for cmd in config.provisions {
                println!("cmd: {:?}", cmd);
                bootloader.run_command(cmd)?;
            }

            return Ok(());
        }

        //if let Some(command) = args.subcommand_matches("fingerprint-certificates") {
        Subcommands::FingerprintCertificates { config } => {
            use lpc55::pki::{Certificates, Pki};
            let pki = Pki::try_from(&*config)?;
            let certificates = Certificates::try_from_pki(&pki)?;
            let fingerprint = certificates.fingerprint();
            println!("{}", hex_str!(&fingerprint.0, 4));
        }

        Subcommands::SignFw {
            config,
            image,
            signed_image,
        } => {
            use lpc55::{secure_binary::Config, signed_binary::ImageSigningRequest};
            let mut config = Config::try_from(&*config)?;
            if let Some(image) = image {
                config.firmware.image = image;
            }
            if let Some(signed_image) = signed_image {
                config.firmware.signed_image = signed_image;
            }
            // let _signed_image = lpc55::signed_binary::sign(&config)?;
            let signing_request = ImageSigningRequest::try_from(&config)?;
            let signed_image = signing_request.sign();
            fs::write(&config.firmware.signed_image, signed_image.0)?;

            //////////////////////////////////////////////////////
            //
            // TODO NEXT: use ImageSigningRequest
            // THEN: make sure uri-certificates in Config work
            //
            //////////////////////////////////////////////////////
        }

        Subcommands::AssembleSb {
            config,
            signed_image,
            secure_boot_image,
            product_version,
            product_major,
            product_minor,
            product_date,
        } => {
            use lpc55::secure_binary::{SignedSb21File, UnsignedSb21File};
            let mut config = lpc55::secure_binary::Config::try_from(&*config)?;
            if let Some(signed_image) = signed_image {
                config.firmware.signed_image = signed_image;
            }
            if let Some(secure_boot_image) = secure_boot_image {
                config.firmware.secure_boot_image = secure_boot_image;
            }
            if let Some(product_version) = product_version {
                config.firmware.product =
                    lpc55::secure_binary::Version::from(product_version.as_str());
            }
            if let Some(product_major) = product_major {
                config.firmware.product.major = product_major.parse()?;
            }
            if let Some(product_minor) = product_minor {
                config.firmware.product.minor = product_minor.parse()?;
            }
            if let Some(product_date) = product_date {
                use chrono::naive::NaiveDate;
                let date = NaiveDate::parse_from_str(&product_date, "%Y-%m-%d")
                    .or_else(|_| NaiveDate::parse_from_str(&product_date, "%Y%m%d"))
                    .or_else(|_| NaiveDate::parse_from_str(&product_date, "%y%m%d"))?;
                let days_since_twenties =
                    (date - NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()).num_days();
                assert!(days_since_twenties > 0);
                info!(
                    "overriding product.major with date {}, i.e. {}",
                    &date, days_since_twenties
                );
                config.firmware.product.minor = days_since_twenties as u16;
            }
            let unsigned_image = UnsignedSb21File::try_assemble_from(&config)?;
            let signing_key =
                lpc55::pki::SigningKey::try_from_uri(config.pki.signing_key.as_ref())?;
            // dbg!(&signing_key);
            let signed_image: SignedSb21File = unsigned_image.sign(&signing_key);
            let signed_image_bytes = signed_image.to_bytes();
            fs::write(&config.firmware.secure_boot_image, signed_image_bytes)?;
            // dbg!(signed_image_bytes.len());
        }

        Subcommands::Sb(subcommand) => match subcommand {
            cli::Sb::Show { file } => {
                lpc55::secure_binary::show(&file)?;
            }
        },
    }

    Ok(())
}

////////
// bootloader.info();

// println!("current version: {}", bootloader.properties().current_version().unwrap());
// println!("target version: {}", bootloader.properties().target_version().unwrap());
// println!("available commands: {:?}", bootloader.properties().available_commands().unwrap());
// println!("available peripherals: {:?}", bootloader.properties().available_peripherals().unwrap());
// println!("PFR (protected flash region) keystore update options: {:?}",
//     bootloader.properties().pfr_keystore_update_option().unwrap());
// println!("RAM start address: 0x{:08X}", bootloader.properties().ram_start_address().unwrap());
// println!("RAM size: {}", bootloader.properties().ram_size().unwrap());
// println!("flash start address: 0x{:08X}", bootloader.properties().flash_start_address().unwrap());
// println!("flash size: {}", bootloader.properties().flash_size().unwrap());
// println!("flash page size: {}", bootloader.properties().flash_page_size().unwrap());
// println!("flash sector size: {}", bootloader.properties().flash_sector_size().unwrap());
// println!("verify writes: {}", bootloader.properties().verify_writes().unwrap());
// println!("flash locked: {}", bootloader.properties().flash_locked().unwrap());
// println!("max packet size: {}", bootloader.properties().max_packet_size().unwrap());
// println!("device UUID: 0x{:16X}", bootloader.properties().device_uuid().unwrap());
// println!("system UUID: 0x{:08X}", bootloader.properties().system_uuid().unwrap());
// println!("CRC check status: {:?}", bootloader.properties().crc_check_status().unwrap());
// println!("reserved regions:");
// for (left, right) in bootloader.properties().reserved_regions().unwrap().iter() {
//     println!("  0x{:08X} - 0x{:08X} ({:.2} KB)", left, right, ((*right + 1) as f64 - *left as f64)/1024.);
// }
// println!("IRQ notification PIN: {:?}", bootloader.properties().irq_notification_pin().unwrap());
