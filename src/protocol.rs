// https://www.nxp.com/docs/en/reference-manual/MCUBOOTRM.pdf
//
// - all fields in packets are little-endian
// - each command sent from host is replied to with response
// - optional data phase, either command or response (not both!)
//   RM uses "incoming" (host->MCU) and "outgoing" (host<-MCU) terminology
//
// 1) no data phase:
//   -> command
//   <- ACK
//   <- generic response
//   -> ACK
//
// 2) command ("incoming") data phase:
//   -> command (has-data-phase flag set)
//   <- ACK
//   <- initial generic response
//   -> ACK
//   -> data
//   <- ACK
//   ...
//   -> final data
//   <- ACK
//   <- final generic response
//   -> ACK
//
// 3) response ("outgoing") data phase:
//   -> cmmand
//   <- ACK
//   <- initial response (has-data-phase flag set)
//   -> ACK
//   <- initial data packet
//   -> ACK
//   ...
//   <- final data packet
//   -> ACK

use hidapi::{HidDevice, HidResult};

pub struct Protocol {
    device: HidDevice,
}

impl Protocol {
    pub fn write(&self, data: &[u8]) -> HidResult<usize> {
        self.device.write(data)
    }

    pub fn read_timeout(&self, timeout: usize) -> HidResult<Vec<u8>> {
        let mut data = Vec::new();
        data.resize(256, 0);
        let read = self.device.read_timeout(&mut data, timeout as i32)?;
        data.resize(read, 0);
        Ok(data)
    }
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

