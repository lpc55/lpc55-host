use core::convert::TryInto;

use hidapi::HidApi;
use enum_iterator::IntoEnumIterator;

use crate::protocol::Protocol;
use crate::status::BootloaderError;
use crate::types::*;
use crate::Result;

#[derive(Debug)]
pub struct Bootloader {
    protocol: Protocol,
    // move around; also "new" should scan the device_list iterator
    // to pull out all the info
    vid: u16,
    pid: u16,
}

impl Bootloader {
    pub fn try_new(vid: u16, pid: u16) -> Result<Self> {
        let api = HidApi::new()?;
        let device = api.open(vid, pid)?;
        let protocol = Protocol::new(device);
        Ok(Self { protocol, vid, pid } )
    }

    // pub fn command(&self, command: Command) {
    // }

    pub fn info(&self) {
        for property in Property::into_enum_iter() {
            println!("\n{:?}", property);
            self.property(property).ok();
        }
    }

    /// TODO: Need to expect erorrs such as: `Response status = 139 (0x8b) kStatus_FLASH_NmpaUpdateNotAllowed`
    /// This happens with `read-memory $((0x0009_FC70)) 16`, which would be the UUID
    ///
    /// TODO: Need to expect errors such as: `Response status = 10200 (0x27d8) kStatusMemoryRangeInvalid`
    /// This happens with `read-memory $((0x5000_0FFC)) 1`, which would be the DIEID (for chip rev)
    pub fn read_memory(&self, address: usize, length: usize) -> Vec<u8> {
        let mut data = Vec::new();
        let mut remaining = length;
        let mut address = address;
        while remaining > 0 {
            let length = core::cmp::min(remaining, 512);
            data.extend_from_slice(&self.read_memory_at_most_512(address, length));
            remaining -= length;
            address += length;
        }
        data
    }

    pub fn read_memory_at_most_512(&self, address: usize, length: usize) -> Vec<u8> {

        // construct
        let packet = Command::ReadMemory { address, length }.hid_packet();

        // send
        // println!("send ({}): {}", packet.len(), to_hex_string(&packet));
        let _wrote = self.protocol.write(packet.as_slice()).expect("could not write");
        //assert_eq!(_wrote, packet.len());

        // expected memory readout from `blhost`:
        // 00 00 04 20 c7 56 00 00 0b 57 00 00 5d 8d 00 00
        // 0b 57 00 00 0b 57 00 00 0b 57 00 00 0b 57 00 00
        // 00 00 00 00 00 00 00 00 00 00 00 00 0b 57 00 00
        // 0b 57 00 00 00 00 00 00 0b 57 00 00 0b 57 00 00

        // what happens:
        // - we send
        //                         Read    n_parms   addr     amount 512
        // send (36): 01 00 20 00  03 00 00 02  00 00 00 00  00 02 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
        //                0xC = 12 = header + 2 params                                                                                     Junk ->
        // read (60): 03 00 0C 00  A3 01 00 02  00 00 00 00  00 02 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  FA AB D2 99 02 F0 23 F9 FF E7 F4 A8 05 F0 05 FC CF 90 FF E7 CF 98 00 F0
        //
        // read (60): 04 00 38 00  00 00 04 20 C7 56 00 00 0B 57 00 00 5D 8D 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0B 57 00 00 0B 57 00 00 00 00 00 00
        // read (60): 04 00 38 00  0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00
        // read (60): 04 00 38 00  0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        // read (60): 04 00 38 00  00 00 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 00 00 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 00 00 00 00
        // read (60): 04 00 38 00  00 00 00 00 00 00 00 00 0B 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 00 00 00 00 0B 57 00 00 0B 57 00 00 0B 57 00 00 00 00 00 00
        // read (60): 04 00 38 00  0B 57 00 00 00 00 00 00 0B 57 00 00 00 00 00 00 0B 57 00 00 0B 57 00 00 80 B5 6F 46 00 F0 01 F8 FE DE B0 B5 02 AF AD F5 06 5D 0D F5 A3 50 D5 A9 D4 90 08 46 02 F0 8C F9
        // read (60): 04 00 38 00  FF E7 F0 A8 01 F0 59 FF FF E7 60 20 03 F0 C1 FB D3 90 FF E7 EC A8 F0 A9 D3 9A 01 F0 68 FF FF E7 68 46 E6 A9 01 60 E9 A8 EC A9 E4 AA E5 AB 04 F0 D3 FD FF E7 48 F6 9C 51
        // read (60): 04 00 38 00  C0 F2 00 01 E9 A8 02 F0 3E F8 8D F8 A0 13 E7 90 FF E7 48 F6 C0 50 C0 F2 00 00 01 68 48 F6 D8 50 C0 F2 00 00 00 68 FC 90 FC 98 D4 9A C2 F8 1C 0C 42 F2 95 03 C0 F2 00 03
        // read (60): 04 00 38 00  D2 91 19 46 05 F0 00 F9 D1 90 D0 91 FF E7 D1 98 FA 90 D0 99 FB 91 6A 46 01 23 13 60 F4 A8 02 22 FA AB D2 99 02 F0 23 F9 FF E7 F4 A8 05 F0 05 FC CF 90 FF E7 CF 98 00 F0
        // read (60): 04 00 08 00  01 00 48 F6 DC 51 C0 F2 D1 90 D0 91 FF E7 D1 98 FA 90 D0 99 FB 91 6A 46 01 23 13 60 F4 A8 02 22 FA AB D2 99 02 F0 23 F9 FF E7 F4 A8 05 F0 05 FC CF 90 FF E7 CF 98 00 F0
        //
        // read (60): 03 00 0C 00  A0 00 00 02  00 00 00 00  03 00 00 00  FF E7 D1 98 FA 90 D0 99 FB 91 6A 46 01 23 13 60 F4 A8 02 22 FA AB D2 99 02 F0 23 F9 FF E7 F4 A8 05 F0 05 FC CF 90 FF E7 CF 98 00 F0
        // read (0):

        // fetch response
        let initial_generic_response = self.protocol.read_timeout(2000).expect("generic reponse first");
        // dbg!(to_hex_string(&initial_generic_response));
        assert_eq!([0x03, 0x00, 0x0C, 0x00], &initial_generic_response[..4]);
        assert_eq!([0xA3, 0x01, 0x00, 0x02], &initial_generic_response[4..][..4]);

        let mut remaining = length;
        let mut data = Vec::new();
        while remaining > 0 {
            // dbg!(remaining);
            let response = self.protocol.read_timeout(2000).expect("could not read");
            assert!(response.len() >= 5);
            // dbg!(to_hex_string(&response));
            // println!("read ({}): {}", response.len(), to_hex_string(&response));
            let [report_id, _, count, _]: [u8; 4] = response.as_slice()[..4].try_into().unwrap();
            assert_eq!(report_id, ReportId::DataIn as u8);
            let count = count as usize;
            assert!(response.len() >= 4 + count);
            assert!(count as usize <= remaining);
            data.extend_from_slice(&response[4..][..count]);
            remaining -= count;
        }

        let final_generic_response = self.protocol.read_timeout(2000).expect("generic reponse first");
        assert_eq!([0x03, 0x00, 0x0C, 0x00], &final_generic_response[..4]);
        assert_eq!([0xA0, 0x00, 0x00, 0x02], &final_generic_response[4..][..4]);

        data
    }

    // INFO:MBOOT:CMD: GetProperty(CurrentVersion, index=0)
    // DEBUG:MBOOT:TX-PACKET: Tag=GetProperty, Flags=0x00, P[0]=0x00000001, P[1]=0x00000000
    // DEBUG:MBOOT:USB:report-id == 1
    // DEBUG:MBOOT:USB:HID-HEADER[4]: 01 00 20 00
    // DEBUG:MBOOT:USB:OUT[59]: 01 00 20 00 07 00 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    // writing 01 00 20 00 07 00 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00, (index: 32
    // DEBUG:MBOOT:USB:IN [59]: 03 00 0C 00 A7 00 00 02 00 00 00 00 00 00 03 4B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    // DEBUG:MBOOT:RX-PACKET: Tag=GetPropertyResponse, Status=Success, V[0]=0x4B030000
    // INFO:MBOOT:CMD: Done successfully

    fn property(&self, property: Property) -> std::result::Result<Vec<u32>, BootloaderError> {

        // construct command
        let packet = Command::GetProperty(property).hid_packet();

        // send command
        // println!("writing {:02x?}", &packet);
        let _wrote = self.protocol.write(packet.as_slice()).expect("could not write");
        // assert_eq!(_wrote, packet.len());

        // fetch response
        let response = self.protocol.read_timeout(2000).expect("could not read");
        // println!("read: {:?}", &response[..read]);

        // interpret response
        let (hid_header, rest) = response.split_at(4);
        assert_eq!(hid_header[..2], (ReportId::CommandIn as u8 as u16).to_le_bytes());

        let (packet_header, rest) = rest.split_at(4);
        assert_eq!(packet_header[..3], [Response::GetProperty as u8, 0, 0]);
        let num_params = packet_header[3];
        assert!(num_params >= 1);

        // status
        let (status, rest) = rest.split_at(4);
        let status = u32::from_le_bytes(status.as_ref().try_into().unwrap());
        if status != 0 {
            return Err(BootloaderError::from(status));
        }

        let mut values = Vec::new();
        for value_bytes in rest.chunks_exact(4).take(num_params as usize - 1) {
            let value = u32::from_le_bytes(value_bytes.as_ref().try_into().unwrap());
            values.push(value);
            // println!("value: {:02x?} (0x{:08x} = {})", value_bytes, value, value);
        }

        Ok(values)
    }

    pub fn properties(&self) -> GetProperties<'_> {
        GetProperties { bl: self }
    }

    pub fn all_properties(&self) -> Properties {
        let proxy = self.properties();
        Properties {
            current_version: proxy.current_version().unwrap(),
            target_version: proxy.target_version().unwrap(),
            available_commands: proxy.available_commands().unwrap(),
            available_peripherals: proxy.available_peripherals().unwrap(),
            pfr_keystore_update_option: proxy.pfr_keystore_update_option().unwrap(),
            ram_start_address: proxy.ram_start_address().unwrap(),
            ram_size: proxy.ram_size().unwrap(),
            flash_start_address: proxy.flash_start_address().unwrap(),
            flash_size: proxy.flash_size().unwrap(),
            flash_page_size: proxy.flash_page_size().unwrap(),
            flash_sector_size: proxy.flash_sector_size().unwrap(),
            verify_writes: proxy.verify_writes().unwrap(),
            flash_locked: proxy.flash_locked().unwrap(),
            max_packet_size: proxy.max_packet_size().unwrap(),
            device_uuid: proxy.device_uuid().unwrap(),
            system_uuid: proxy.system_uuid().unwrap(),
            crc_check_status: proxy.crc_check_status().unwrap(),
            reserved_regions: proxy.reserved_regions().unwrap(),
            irq_notification_pin: proxy.irq_notification_pin().unwrap(),
        }
    }
}

pub struct GetProperties<'a> {
    bl: &'a Bootloader
}

impl GetProperties<'_> {
    pub fn current_version(&self) -> std::result::Result<Version, BootloaderError> {
        Ok(Version::from(self.bl.property(Property::CurrentVersion)?[0]))
    }
    pub fn target_version(&self) -> std::result::Result<Version, BootloaderError> {
        Ok(Version::from(self.bl.property(Property::TargetVersion)?[0]))
    }
    pub fn ram_start_address(&self) -> std::result::Result<usize, BootloaderError> {
        Ok(self.bl.property(Property::RamStartAddress)?[0] as _)
    }
    pub fn ram_size(&self) -> std::result::Result<usize, BootloaderError> {
        Ok(self.bl.property(Property::RamSize)?[0] as _)
    }
    pub fn flash_start_address(&self) -> std::result::Result<usize, BootloaderError> {
        Ok(self.bl.property(Property::FlashStartAddress)?[0] as _)
    }
    pub fn flash_size(&self) -> std::result::Result<usize, BootloaderError> {
        Ok(self.bl.property(Property::FlashSize)?[0] as _)
    }
    pub fn flash_page_size(&self) -> std::result::Result<usize, BootloaderError> {
        Ok(self.bl.property(Property::FlashPageSize)?[0] as _)
    }
    pub fn flash_sector_size(&self) -> std::result::Result<usize, BootloaderError> {
        Ok(self.bl.property(Property::FlashSectorSize)?[0] as _)
    }
    pub fn max_packet_size(&self) -> std::result::Result<usize, BootloaderError> {
        Ok(self.bl.property(Property::MaxPacketSize)?[0] as _)
    }
    pub fn available_peripherals(&self) -> std::result::Result<crate::types::AvailablePeripherals, BootloaderError> {
        Ok(AvailablePeripherals::from_bits_truncate(self.bl.property(Property::AvailablePeripherals)?[0]))
    }
    pub fn available_commands(&self) -> std::result::Result<crate::types::AvailableCommands, BootloaderError> {
        Ok(AvailableCommands::from_bits_truncate(self.bl.property(Property::AvailableCommands)?[0]))
    }
    pub fn pfr_keystore_update_option(&self) -> std::result::Result<crate::types::PfrKeystoreUpdateOptions, BootloaderError> {
        let values = self.bl.property(Property::PfrKeystoreUpdateOptions)?;
        assert_eq!(values.len(), 1);
        Ok(PfrKeystoreUpdateOptions::from(values[0]))
    }
    pub fn verify_writes(&self) -> std::result::Result<bool, BootloaderError> {
        Ok(self.bl.property(Property::VerifyWrites)?[0] == 1)
    }
    pub fn flash_locked(&self) -> std::result::Result<bool, BootloaderError> {
        Ok(match self.bl.property(Property::FlashSecurityState)?[0] {
            0x0 | 0x5AA55AA5 => false,
            0x1 | 0xC33CC33C => true,
            _ => panic!(),
        })
    }
    pub fn device_uuid(&self) -> std::result::Result<u128, BootloaderError> {
        let values = self.bl.property(Property::UniqueDeviceIdent)?;
        assert_eq!(values.len(), 4);
        Ok(
            ((values[3] as u128) << 96) +
            ((values[2] as u128) << 64) +
            ((values[1] as u128) << 32) +
            ((values[0] as u128))
        )
    }
    pub fn system_uuid(&self) -> std::result::Result<u64, BootloaderError> {
        let values = self.bl.property(Property::SystemDeviceIdent)?;
        assert_eq!(values.len(), 2);
        Ok(((values[1] as u64) << 32) + (values[0] as u64))
    }

    pub fn crc_check_status(&self) -> std::result::Result<BootloaderError, BootloaderError> {
        Ok(BootloaderError::from(self.bl.property(Property::CrcCheckStatus)?[0]))
    }

    pub fn reserved_regions(&self) -> std::result::Result<Vec<(usize, usize)>, BootloaderError> {
        let values = self.bl.property(Property::ReservedRegions)?;
        assert_eq!(values.len() % 2, 0);
        let mut pairs = Vec::new();
        for pair in values.chunks_exact(2) {
            let left = pair[0];
            let right = pair[1];
            assert!(right >= left);
            if right > left {
                pairs.push((left as usize, right as usize));
            }
        }
        Ok(pairs)
    }

    pub fn irq_notification_pin(&self) -> std::result::Result<crate::types::IrqNotificationPin, BootloaderError> {
        Ok(IrqNotificationPin::from(self.bl.property(Property::IrqNotificationPin)?[0]))
    }
}

#[cfg(test)]
#[test]
fn test_all_properties() {
    let (vid, pid) = (0x1fc9, 0x0021);
    let bootloader = Bootloader::try_new(vid, pid).unwrap();
    insta::assert_debug_snapshot!(bootloader.all_properties());
}
