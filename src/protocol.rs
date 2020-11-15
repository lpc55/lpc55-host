// https://www.nxp.com/docs/en/reference-manual/MCUBOOTRM.pdf
//
// - all fields in packets are little-endian
// - each command sent from host is replied to with response
// - optional data phase, either command or response (not both!)
//   RM uses "incoming" (host->MCU) and "outgoing" (host<-MCU) terminology
//
//
// 1) no data phase:
//   --> command
//   <-- generic response
//
//
// 2) command data phase:
//   --> command (has-data-phase flag set)
//   <-- initial generic response (must signal success status to proceed with data phase)
//   ==> inital command data packet
//   ⋮
//   ==> final command data packet
//   <-- final generic response (contains status for entire operation)
//
//  Device may abort data phase by sending finale generic response early, with status abort
//
//
// 3) response data phase:
//   --> command
//   <-- initial non-generic response (must signal has-data to proceed with data phase)
//   <== initial response data packet
//    ⋮
//   <== final reponse data packet
//   <-- final generic response (contains status for entire operation)
//
//  Device may abort data phase early by sending zero-length packet
//  Host may abort data phase by sending generic response (?is this a thing?)

use core::convert::{TryFrom, TryInto};
use crate::types;

use hidapi::{HidDevice, HidResult};

pub struct Protocol {
    device: HidDevice,
}

pub struct ResponsePacket {
    pub tag: types::ResponseTag,
    pub has_data: bool,
    pub status: Option<types::BootloaderError>,
    // pub mirrored_command_header: [u8; 4],
    pub parameters: Vec<u32>,
}

pub enum ReceivedPacket {
    Response(ResponsePacket),
    Data(Vec<u8>),
}

pub const READ_TIMEOUT: i32 = 2000;

impl Protocol {

    pub fn call(&self, command: &types::Command) -> anyhow::Result<types::Response> {

        // construct command packet
        let command_packet = command.hid_packet();

        // send command packet
        self.write(command_packet.as_slice())?;
        trace!(" --> {}", types::to_hex_string(&command_packet));

        let initial_response = self.read_packet()?;

        // parse initial reponse packet
        // use types::CommandTag as Tag;
        match (*command, command.tag(), command.data_phase()) {

            // case 1: no data phases
            (command, _tag, types::DataPhase::None) => {

                // we expect a non-data packet, not signaling additional data packets, with
                // successful status, mirroring our command header
                if let ReceivedPacket::Response(packet) = initial_response {
                    assert_eq!(packet.has_data, false);
                    assert!(packet.status.is_none());
                    match command {
                        types::Command::KeyProvisioning(types::KeyProvisioningOperation::Enroll) => {
                            assert_eq!(packet.tag, types::ResponseTag::Generic);

                            // general property of generic responses: 2 parameters, status and mirrored command header
                            assert_eq!(packet.parameters.len(), 1);
                            assert_eq!(packet.parameters[0].to_le_bytes(), command.header());

                            Ok(types::Response::Generic)
                        }
                        types::Command::GetProperty(_property) => {
                            assert_eq!(packet.tag, types::ResponseTag::GetProperty);
                            assert!(!packet.parameters.is_empty());

                            Ok(types::Response::GetProperty(packet.parameters))
                        }
                        _ => todo!()
                    }
                } else {
                    todo!();
                }
            }

// old
// "04003800 00000000 02000000 02000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 02000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
// "04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 ECE6A668 2922E9CC F462A95F DF81E180 E1528642 7C520098"
// "04000800 2C80BA51 B067AF3C 00000000 00000000 00000000 00000000 00000000 00000000 ECE6A668 2922E9CC F462A95F DF81E180 E1528642 7C520098"
// "04003800 00000000 02000000 02000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"

// new
// 03000C00 A3010002 00000000 00020000
// 04003800 00000000 02000000 02000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 02000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 (60 bytes)
// 04003800 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 ECE6A668 2922E9CC F462A95F DF81E180 E1528642 7C520098 (60 bytes)

            (types::Command::ReadMemory { address: _, length }, _, _) => {

                if let ReceivedPacket::Response(packet) = initial_response {
                    // assert_eq!([0x03, 0x00, 0x0C, 0x00], &initial_generic_response[..4]);
                    assert_eq!(packet.has_data, true);
                    assert!(packet.status.is_none());
                    assert_eq!(packet.tag, types::ResponseTag::ReadMemory);

                    // ReadMemory response: 2 parameters, status and then number of bytes to be
                    // sent in data phase
                    assert_eq!(packet.parameters.len(), 1);
                    assert_eq!(packet.parameters[0] as usize, length);

                    let mut data = Vec::new();
                    while data.len() < length {
                        let maybe_data_packet = self.read_packet()?;
                        if let ReceivedPacket::Data(partial_data) = maybe_data_packet {
                            assert!(data.len() + partial_data.len() <= length);
                            data.extend_from_slice(&partial_data);
                        } else {
                            todo!();
                        }
                    }

                    let maybe_final_generic_packet = self.read_packet()?;

                    if let ReceivedPacket::Response(packet) = maybe_final_generic_packet {
                        assert_eq!(packet.has_data, false);
                        assert!(packet.status.is_none());

                        assert_eq!(packet.tag, types::ResponseTag::Generic);
                        // general property of generic responses: 2 parameters, status and mirrored command header
                        assert_eq!(packet.parameters.len(), 1);
                        // it seems the device "forgets" about the parameters the original command
                        // contained (address + length)
                        // ooorrr, Table 4-11 ("The Command tag parameter identifies the response to the command sent by the host.")
                        // just means that the command tag is set
                        assert_eq!(packet.parameters[0].to_le_bytes()[..2], command.header()[..2]);

                        Ok(types::Response::ReadMemory(data))
                    } else {
                        todo!();
                    }

                } else {
                    todo!();
                }
            }
            _ => todo!()
        }
    }

    pub fn read_packet(&self) -> anyhow::Result<ReceivedPacket> {

        // read data with timeout
        let mut data = Vec::new();
        data.resize(256, 0);
        let read = self.device.read_timeout(&mut data, READ_TIMEOUT)?;
        data.resize(read, 0);

        // todo: what errors are appropriate? e.g. if report ID is invalid
        let report_id = types::ReportId::try_from(data[0]).unwrap();

        // the device often sends "extra junk"
        // we split this off early
        let expected_packet_len = u16::from_le_bytes(data[2..4].try_into().unwrap()) as usize;
        data.resize(4 + expected_packet_len, 0);
        trace!("<-- {} ({} bytes)", types::to_hex_string(&data), data.len());

        let response_packet = data.split_off(4);

        // now handle the response packet
        Ok(match report_id {
            types::ReportId::Response => {
                let tag = types::ResponseTag::try_from(response_packet[0]).unwrap();
                let has_data = (response_packet[1] & 1) != 0;
                let expected_param_count = response_packet[3] as usize;

                let mut parameters: Vec<u32> = response_packet[4..].chunks(4)
                    .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                    .collect();
                assert_eq!(expected_param_count, parameters.len());

                // first parameter is always status
                let status_code = parameters.remove(0);
                let status = match status_code {
                    0 => None,
                    code => Some(types::BootloaderError::from(code)),
                };

                // NB: this is only true for Generic responses
                // // second parameter is always mirrored command header
                // let mirrored_command_header = parameters.remove(0).to_le_bytes();

                ReceivedPacket::Response(ResponsePacket {
                    tag,
                    has_data,
                    status,
                    // mirrored_command_header,
                    parameters,
                })

            },
            types::ReportId::ResponseData => {
                ReceivedPacket::Data(response_packet)
            },
            _ => todo!()
        })
    }

    pub fn write(&self, data: &[u8]) -> HidResult<()> {
        // hidapi::HidError::IncompleteSendError { sent: usize, all: usize } exists but is not checked :/
        let sent = self.device.write(data)?;
        let all = data.len();
        if sent != all {
            return Err(hidapi::HidError::IncompleteSendError { sent, all });
        }
        Ok(())
    }

    pub fn read_timeout_parsed(&self, timeout: usize) -> HidResult<(
        types::ReportId, types::ResponseTag, Option<types::BootloaderError>, u32, Vec<u32>, bool,
    )> {
        let mut data = Vec::new();
        data.resize(256, 0);
        let read = self.device.read_timeout(&mut data, timeout as i32)?;
        data.resize(read, 0);

        dbg!(types::to_hex_string(&data));
        // first 4 bytes contain HID packet parameters
        let report_id = types::ReportId::try_from(data[0]).unwrap();
        let hid_packet_len = u16::from_le_bytes(data[2..4].try_into().unwrap()) as usize;

        // now comes the response packet
        let response_packet = &data[4..][..hid_packet_len];

        // let [tag, flags, _, param_count, ..] = response_packet;
        let tag = response_packet[0];
        let flags = response_packet[1];
        let param_count = response_packet[3];

        let data_follows = (flags & 1) != 0;
        let response = types::ResponseTag::try_from(tag).unwrap();

        let mut params: Vec<u32> = response_packet[4..].chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(param_count as usize, params.len());

        // first parameter is always status
        let status_code = params.remove(0);
        let error = match status_code {
            0 => None,
            code => Some(types::BootloaderError::from(code)),
        };

        let command = params.remove(0);

        Ok((report_id, response, error, command, params, data_follows))
    }

    pub fn read_timeout(&self, timeout: usize) -> HidResult<Vec<u8>> {
        let mut data = Vec::new();
        data.resize(256, 0);
        let read = self.device.read_timeout(&mut data, timeout as i32)?;
        data.resize(read, 0);
        Ok(data)
    }

    // pub fn read_expected(&self, expected: usize, timeout: usize) -> HidResult<Vec<u8>> {
    //     let mut data = Vec::new();
    //     data.resize(expected, 0);
    //     let mut remaining = expected;
    //     while remaining > 0 {
    //         let read = self.device.read_timeout(&mut data, timeout as i32)?;
    //         remaining -= read;
    //     }
    //     // data.resize(read, 0);
    //     Ok(data)
    // }
}

impl Protocol {
    pub fn new(device: HidDevice) -> Self {
        Self { device }
    }
}

impl std::fmt::Debug for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            // .debug_struct("HidDevice")
                .field("manufacturer", &self.device.get_manufacturer_string())
                .field("product", &self.device.get_product_string())
                .field("serial number", &self.device.get_serial_number_string())
            // .finish()
        .finish()
    }
}

