// use core::convert::{TryFrom, TryInto};
use core::convert::TryFrom;
use std::io::{self, Write as _};

fn main() {
    // if let Err(err) = Args::parse().and_then(try_main) {
    let args = lpc55::cli::app::app().get_matches();
    if let Err(err) = try_main(args) {
        eprintln!("{}", err);
        std::process::exit(2);
    }
}

fn hexadecimal_value(input: &str) -> nom::IResult<&str, u16> {
    use nom::{
        combinator::map_res,
        sequence::preceded,
        branch::alt,
        bytes::complete::tag,
        combinator::recognize,
        multi::many1,
        sequence::terminated,
        character::complete::one_of,
        multi::many0,
        character::complete::char,
    };

  map_res(
    preceded(
      alt((tag("0x"), tag("0X"))),
      recognize(
        many1(
          terminated(one_of("0123456789abcdefABCDEF"), many0(char('_')))
        )
      )
    ),
    |out: &str| u16::from_str_radix(&str::replace(&out, "_", ""), 16)
  )(input)
}

// fn try_main(args: Args) -> Result<()> {
fn try_main(args: clap::ArgMatches<'_>) -> lpc55::cli::args::Result<()> {

    lpc55::logger::Logger::init().unwrap();

     match args.occurrences_of("v") {
        // 0 => log::set_max_level(log::LevelFilter::Error),
        0 => log::set_max_level(log::LevelFilter::Warn),
        1 => log::set_max_level(log::LevelFilter::Info),
        2 => log::set_max_level(log::LevelFilter::Debug),
        3 | _ => log::set_max_level(log::LevelFilter::Trace),
    };

    // TODO: graceful parse error handling
    // let vid = u16::from_str_radix(args.value_of("vid").unwrap().trim_start_matches("0x"), 16).unwrap();
    let (_, vid) = hexadecimal_value(args.value_of("VID").unwrap()).unwrap();
    let pid = u16::from_str_radix(args.value_of("PID").unwrap().trim_start_matches("0x"), 16).unwrap();

    let bootloader = lpc55::bootloader::Bootloader::try_new(vid, pid).unwrap();
    // debug!("{:?}", &bootloader);

    if let Some(command) = args.subcommand_matches("http") {
        let addr = command.value_of("ADDR").unwrap().to_string();
        let port = u16::from_str_radix(command.value_of("PORT").unwrap(), 10).unwrap();
        let http_config = lpc55::http::HttpConfig { addr, port, timeout_ms: 5000 };
        let server = lpc55::http::Server::new(&http_config, bootloader)?;
        server.run()?;
        return Ok(());
    }

    if let Some(_command) = args.subcommand_matches("info") {
        bootloader.info();
        println!("{:#?}", bootloader.all_properties());
        return Ok(());
    }

    if let Some(subcommand) = args.subcommand_matches("keystore") {
        if subcommand.subcommand_matches("enroll").is_some() {
            bootloader.enroll_puf();
            return Ok(());
        }

        if subcommand.subcommand_matches("read").is_some() {
            // let data = bootloader.read_memory(0x9_DE60, 3*512);

            let command = lpc55::types::Command::Keystore(
                lpc55::types::KeystoreOperation::ReadKeystore
            );
            let response = bootloader.protocol.call(&command).expect("success");

            let data = if let lpc55::types::Response::Data(data) = response {
                data
            } else {
                todo!();
            };

            let keystore = lpc55::pfr::Keystore::try_from(data.as_slice()).unwrap();
            println!("{}", serde_json::to_string(&keystore).unwrap());
            return Ok(());
        }

        if let Some(command) = subcommand.subcommand_matches("set-key") {
            let key = lpc55::types::Key::try_from(command.value_of("KEY").unwrap()).unwrap();
            let keydata_filename = command.value_of("KEYDATA_FILENAME").unwrap();
            let data = std::fs::read(keydata_filename)?;

            let command = lpc55::types::Command::Keystore(
                lpc55::types::KeystoreOperation::SetKey { key, data }
            );

            bootloader.protocol.call(&command).expect("success");
            return Ok(());
        }

    }

    if let Some(command) = args.subcommand_matches("pfr") {
        let data = bootloader.read_memory(0x9_DE00, 7*512);
        // let empty = data.iter().all(|&byte| byte == 0);
        // if empty {
        //     println!("PFR region is completely zeroed out");
        // } else {
        //     println!("PFR region is not completely zeroed out");
        // }
        let pfr = lpc55::pfr::ProtectedFlash::try_from(&data[..]).unwrap();
        // println!("PFR = {:#?}", &pfr);
        // println!("PFR = {:?}", &pfr);

        match command.value_of("FORMAT").unwrap() {
            "alt-native" => println!("{:#?}", &pfr),
            "native" => println!("{:?}", &pfr),
            "json" => println!("{}", serde_json::to_string(&pfr).unwrap()),
            "json-pretty" => println!("{}", serde_json::to_string_pretty(&pfr).unwrap()),
            "raw" => {
                if atty::is(atty::Stream::Stdout) {
                    panic!("don't dump binary data to terminal");
                } else {
                    io::stdout().write_all(&data).unwrap()
                }
            }
            "toml" => println!("{}", toml::to_string(&pfr).unwrap()),
            "yaml" => println!("{}", serde_yaml::to_string(&pfr).unwrap()),
            // "yaml-pretty" => println!("{}", serde_yaml::to_string_pretty(&pfr).unwrap()),
            _ => panic!(),
        }
        // let j = serde_json::to_string(&pfr).unwrap();
        // println!("{}", j);

        // println!("CFPA-scratch == CFPA-ping: {}", pfr.field.scratch == pfr.field.ping);
        // println!("CFPA-scratch == CFPA-pong: {}", pfr.field.scratch == pfr.field.pong);
        // println!("CFPA-ping == CFPA-pong: {}", pfr.field.ping == pfr.field.pong);
    }

    if let Some(command) = args.subcommand_matches("read-memory") {
        let address = clap::value_t!(command.value_of("ADDRESS"), usize).unwrap();
        let length = clap::value_t!(command.value_of("LENGTH"), usize).unwrap();
        // let data = bootloader.read_memory_at_most_512(address, length);
        let data = bootloader.read_memory(address, length);

        if let Some(output_filename) = command.value_of("OUTPUT_FILE") {
            let mut file = std::fs::File::create(output_filename)?;
            use std::io::Write;
            file.write_all(&data)?;
            file.sync_all()?;
        } else {
            lpc55::print_hex(data, 16);
        }
        return Ok(());
    }

    if let Some(command) = args.subcommand_matches("rotkh") {
        let config_filename = command.value_of("CONFIG").unwrap();
        lpc55::rotkh::calculate(config_filename)?;
    }

    if let Some(command) = args.subcommand_matches("sign-fw") {
        let config_filename = command.value_of("CONFIG").unwrap();
        let signed_image = lpc55::bintosb::sign(config_filename)?;
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

