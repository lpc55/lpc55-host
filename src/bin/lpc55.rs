use core::convert::{TryFrom, TryInto};

use log::debug;

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

pub fn print_hex(data: impl AsRef<[u8]>, chunk_size: usize) {
    for chunk in data.as_ref().chunks(chunk_size) {
        println!("{}", lpc55::types::to_hex_string(chunk));
    }
}

// fn try_main(args: Args) -> Result<()> {
fn try_main(args: clap::ArgMatches<'_>) -> lpc55::cli::args::Result<()> {

    lpc55::logger::Logger::init().unwrap();

     match args.occurrences_of("v") {
        0 => log::set_max_level(log::LevelFilter::Error),
        1 => log::set_max_level(log::LevelFilter::Warn),
        2 => log::set_max_level(log::LevelFilter::Debug),
        _ => println!("Don't be crazy"),
    };

    // TODO: graceful parse error handling
    // let vid = u16::from_str_radix(args.value_of("vid").unwrap().trim_start_matches("0x"), 16).unwrap();
    let (_, vid) = hexadecimal_value(args.value_of("vid").unwrap()).unwrap();
    let pid = u16::from_str_radix(args.value_of("pid").unwrap().trim_start_matches("0x"), 16).unwrap();

    let bootloader = lpc55::bootloader::Bootloader::try_new(vid, pid).unwrap();
    debug!("{:?}", &bootloader);

    if let Some(_command) = args.subcommand_matches("info") {
        println!("{:#?}", bootloader.all_properties());
        return Ok(());
    }

    if let Some(command) = args.subcommand_matches("pfr") {
        let data = bootloader.read_memory(0x9_DE00, 7*512);
        let pfr = lpc55::pfr::Pfr::try_from(&data[..]).unwrap();
        println!("PFR = {:#?}", &pfr);
        // println!("PFR = {:?}", &pfr);
        todo!("do something with the PFR data");
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
            print_hex(data, 16);
        }
        return Ok(());
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

