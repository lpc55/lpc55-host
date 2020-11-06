use core::convert::TryInto;
use core::fmt;

use nom::{
    IResult,
    number::complete::le_u32,
    named, take,
};

#[derive(Debug)]
pub struct Pfr {
    pub cfpa: Cfpa,
    pub cmpa: Cmpa,
}

#[derive(Debug)]
pub struct CfpaPage<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: CustomerDataCfpaRegion,
    VendorUsage: VendorUsageCfpaRegion,
{
    header: Header,
    version: Version,
    /// monotonic counter
    secure_firmware_version: MonotonicCounter,
    /// monotonic counter
    nonsecure_firmware_version: MonotonicCounter,
    image_key_revocation_id: MonotonicCounter,

    // following three have "upper16 bits are inverse of lower16 bits"
    vendor_usage: VendorUsage,
    rot_keys_status: RotKeysStatus,
    // UM 11126
    // 51.7.1: DCFG_CC = device configuration for credential constraints
    // 51.7.7: SOCU = System-on-Chip Usage
    // PIN = "pinned" or fixed
    debug_settings: DebugSecurityPolicies,
    enable_fa_mode: bool,
    cmpa_prog_in_progress: CmpaProgInProgress,

    prince_ivs: [PrinceIvCode; 3],

    // customer_data: [u32; 4*14],  // or [u128, 14]
    customer_data: CustomerData,
    sha256_hash: Sha256Hash,
}

#[derive(Debug)]
pub struct Cmpa<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: CustomerDataCmpaRegion,
    VendorUsage: VendorUsageCmpaRegion,
{
    boot_configuration: BootConfiguration,
    usb_vid_pid: UsbVidPid,
    debug_settings: DebugSecurityPolicies,
    vendor_usage: VendorUsage,
    secure_boot_configuration: SecureBootConfiguration,
    prince_configuration: PrinceConfiguration,
    prince_subregions: [PrinceSubregion; 3],
    rot_keys_table_hash: Sha256Hash,
    customer_data: CustomerData,
    sha256_hash: Sha256Hash,
}

fn parse_cmpa<CustomerData: CustomerDataCmpaRegion, VendorUsage: VendorUsageCmpaRegion>(input: &[u8])
    -> IResult<&[u8], Cmpa<CustomerData, VendorUsage>>
{
    let (input, boot_cfg) = le_u32(input)?;
    let (input, _spi_flash_cfg) = le_u32(input)?;
    let (input, usb_id) = le_u32(input)?;
    let (input, _sdio_cfg) = le_u32(input)?;
    let (input, cc_socu_pin) = le_u32(input)?;
    let (input, cc_socu_default) = le_u32(input)?;

    let (input, vendor_usage) = le_u32(input)?;
    let (input, secure_boot_cfg) = le_u32(input)?;
    let (input, prince_cfg) = le_u32(input)?;

    let (input, prince_sr_0) = le_u32(input)?;
    let (input, prince_sr_1) = le_u32(input)?;
    let (input, prince_sr_2) = le_u32(input)?;

    // reserved
    let (input, _) = take!(input, 8 * 4)?;

    let (input, rotk_keys_table_hash) = take!(input, 32)?;

    // reserved
    let (input, _) = take!(input, 9 * 4 * 4)?;

    let (input, customer_data) = take!(input, 14 * 4 * 4)?;

    let (input, sha256_hash) = take!(input, 32)?;

    let cmpa = Cmpa {
        boot_configuration: BootConfiguration::from(boot_cfg),
        usb_vid_pid: UsbVidPid::from(usb_id),
        debug_settings: DebugSecurityPolicies::from([cc_socu_default, cc_socu_pin]),
        vendor_usage: VendorUsage::from(vendor_usage),
        secure_boot_configuration: SecureBootConfiguration::from(secure_boot_cfg),
        prince_configuration: PrinceConfiguration::from(prince_cfg),
        prince_subregions: [
            PrinceSubregion(prince_sr_0),
            PrinceSubregion(prince_sr_1),
            PrinceSubregion(prince_sr_2),
        ],
        rot_keys_table_hash: Sha256Hash(rotk_keys_table_hash.try_into().unwrap()),
        customer_data: CustomerData::from(customer_data.try_into().unwrap()),
        sha256_hash: Sha256Hash(sha256_hash.try_into().unwrap()),
    };

    Ok((input, cmpa))
}


#[derive(Debug)]
pub enum BootSpeed {
    Nmpa,
    Fro48,
    Fro96,
    Reserved,
}

impl From<u8> for BootSpeed {
    fn from(value: u8) -> Self {
        use BootSpeed::*;
        match value {
            0b00 => Nmpa,
            0b01 => Fro48,
            0b10 => Fro96,
            0b11 | _ => Reserved,
        }
    }
}

#[derive(Debug)]
pub enum IspMode {
    Auto,
    Usb,
    Uart,
    Spi,
    I2c,
    FallthroughDisabled,
    Reserved(u8),
}

impl From<u8> for IspMode {
    fn from(value: u8) -> Self {
        use IspMode::*;
        match value {
            0b000 => Auto,
            0b001 => Usb,
            0b010 => Uart,
            0b011 => Spi,
            0b100 => I2c,
            0b111 => FallthroughDisabled,
            value => Reserved(value),
        }
    }
}

#[derive(Debug)]
pub struct BootConfiguration {
    pub failure_port: u8,
    pub failure_pin: u8,
    pub speed: BootSpeed,
    pub default_isp_mode: IspMode,
}

impl From<u32> for BootConfiguration {
    fn from(word: u32) -> Self {
        Self {
            failure_port: ((word >> 24) & 0b11) as u8,
            failure_pin: ((word >> 26) & 0b11111) as u8,
            speed: BootSpeed::from(((word >> 7) & 0b11) as u8),
            default_isp_mode: IspMode::from(((word >> 4) & 0b111) as u8),
        }
    }
}

#[derive(Debug)]
pub struct UsbVidPid {
    vid: u16,
    pid: u16,
}

impl From<u32> for UsbVidPid {
    fn from(word: u32) -> Self {
        Self {
            vid: word as _,
            pid: (word >> 16) as _,
        }
    }
}

fn multibool(bits: u32) -> bool {
    match bits {
        0b00 => false,
        0b01 | 0b10 | 0b11 => true,
        _ => panic!(),
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum TrustzoneMode {
    FromImageHeader = 0b00,
    DisabledBootToNonsecure = 0b01,
    EnabledBootToSecure = 0b10,
    // what is this?
    PresetTrustzoneCheckerFromImageHeader = 0b11,
}

impl From<u32> for TrustzoneMode {
    fn from(value: u32) -> Self {
        use TrustzoneMode::*;
        match value {
            0b00 => FromImageHeader,
            0b01 => DisabledBootToNonsecure,
            0b10 => EnabledBootToSecure,
            0b11 => PresetTrustzoneCheckerFromImageHeader,
            _ => panic!(),
        }
    }
}

#[derive(Debug)]
pub struct SecureBootConfiguration {
    secure_boot_enabled: bool,
    puf_enrollment_disabled: bool,
    puf_keycode_generation_disabled: bool,
    trustzone_mode: TrustzoneMode,
    dice_computation_disabled: bool,
    include_cmpa_area_in_dice_computation: bool,
    include_nxp_area_in_dice_computation: bool,
    use_rsa4096_keys: bool,
}

impl From<u32> for SecureBootConfiguration {
    fn from(word: u32) -> Self {
        Self {
            secure_boot_enabled: multibool((word >> 30) & 0b11),
            puf_enrollment_disabled: multibool((word >> 12) & 0b11),
            puf_keycode_generation_disabled: multibool((word >> 10) & 0b11),
            trustzone_mode: TrustzoneMode::from((word >> 8) & 0b11),
            dice_computation_disabled: multibool((word >> 6) & 0b11),
            include_cmpa_area_in_dice_computation: multibool((word >> 4) & 0b11),
            include_nxp_area_in_dice_computation: multibool((word >> 2) & 0b11),
            use_rsa4096_keys: multibool((word >> 0) & 0b11),
        }
    }
}

#[derive(Debug)]
pub struct PrinceConfiguration {
    erase_checks: [bool; 3],
    locked: [bool; 3],
    addresses: [u8; 3],
}

impl From<u32> for PrinceConfiguration {
    fn from(word: u32) -> Self {
        Self {
            erase_checks: [
                multibool((word >> 28) & 0b11),
                multibool((word >> 26) & 0b11),
                multibool((word >> 24) & 0b11),
            ],
            locked: [
                multibool((word >> 20) & 0b11),
                multibool((word >> 18) & 0b11),
                multibool((word >> 16) & 0b11),
            ],
            addresses: [
                ((word >> 8) & 0xF) as _,
                ((word >> 4) & 0xF) as _,
                ((word >> 0) & 0xF) as _,
            ],
        }
    }
}

#[derive(Debug)]
pub struct PrinceSubregion(u32);

impl core::convert::TryFrom<&[u8]> for Pfr {
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let cfpa = Cfpa::try_from(&input[..3*512]).unwrap();
        let cmpa = Cmpa::try_from(&input[3*512..4*512]).unwrap();

        let pfr = Pfr { cfpa, cmpa };

        Ok(pfr)
    }
}

pub trait CustomerDataCfpaRegion: fmt::Debug + From<[u8; 14*4*4]> {}
pub trait CustomerDataCmpaRegion: fmt::Debug + From<[u8; 14*4*4]> {}
pub struct RawCustomerData([u8; 4*4*14]);
impl fmt::Debug for RawCustomerData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        f.write_fmt(format_args!("'{:02x} {:02x} {:02x} (...) {:02x} {:02x} {:02x}'",
                                 bytes[0], bytes[1], bytes[3],
                                 bytes[224-3], bytes[224-2], bytes[224-1],))
        // f.debug_tuple("RawCustomerData")
        //  .field(&self.0)
        //  .finish()
    }
}
impl From<[u8; 14*4*4]> for RawCustomerData {
    fn from(bytes: [u8; 224]) -> Self {
        Self(bytes)
    }
}
impl CustomerDataCfpaRegion for RawCustomerData {}
impl CustomerDataCmpaRegion for RawCustomerData {}


#[derive(Debug)]
pub struct Cfpa<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: CustomerDataCfpaRegion,
    VendorUsage: VendorUsageCfpaRegion,
{
    scratch: CfpaPage<CustomerData, VendorUsage>,
    ping: CfpaPage<CustomerData, VendorUsage>,
    pong: CfpaPage<CustomerData, VendorUsage>,
}

impl core::convert::TryFrom<&[u8]> for Cfpa {
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let scratch = CfpaPage::try_from(&input[..512]).unwrap();
        let ping = CfpaPage::try_from(&input[512..2*512]).unwrap();
        let pong = CfpaPage::try_from(&input[2*512..3*512]).unwrap();

        let cfpa = Cfpa { scratch, ping, pong };

        Ok(cfpa)
    }
}

#[derive(Debug)]
pub struct Header(u32);

#[derive(Debug)]
pub struct Version(u32);

pub trait VendorUsageCfpaRegion: fmt::Debug + From<u32> {}
pub trait VendorUsageCmpaRegion: fmt::Debug + From<u32> {}
pub struct RawVendorUsage(u32);
impl fmt::Debug for RawVendorUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RawVendorUsage")
         .field(&self.0)
         .finish()
    }
}
impl From<u32> for RawVendorUsage {
    fn from(word: u32) -> Self {
        Self(word)
    }
}
impl VendorUsageCfpaRegion for RawVendorUsage {}
impl VendorUsageCmpaRegion for RawVendorUsage {}

pub struct Sha256Hash([u8; 32]);
impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        f.write_fmt(format_args!("'{:02x} {:02x} {:02x} (...) {:02x} {:02x} {:02x}'",
                                 bytes[0], bytes[1], bytes[3],
                                 bytes[32-3], bytes[32-2], bytes[32-1],))
    }
}

/// CMPA Page programming on going. This field shall be set to 0x5CC55AA5 in the active CFPA page each time CMPA page programming is going on. It shall always be set to 0x00000000 in the CFPA scratch area.
pub struct CmpaProgInProgress(u32);

impl fmt::Debug for CmpaProgInProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            // 0x00000000 => f.write_str("empty"),
            0x0000_0000 => f.write_fmt(format_args!("empty (0x{:x})", 0)),
            0x5CC5_5AA5 => f.write_str("CMPA page programming ongoing"),
            value => f.write_fmt(format_args!("unknown value {:x}", value)),
        }
    }
}

#[derive(Debug)]
pub struct RotKeysStatus {
    key_0_status: RotKeyStatus,
    key_1_status: RotKeyStatus,
    key_2_status: RotKeyStatus,
    key_3_status: RotKeyStatus,
}

#[derive(Debug)]
/// Generated and used only by bootloader.
///
/// Not to be modified by user.
pub struct PrinceIvCode(u32);

#[derive(Debug)]
pub struct MonotonicCounter(u32);

impl MonotonicCounter {
    /// not public as the value should be read
    fn from(value: u32) -> Self {
        Self(value)
    }

    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

#[derive(Debug)]
pub enum RotKeyStatus {
    Invalid,
    Enabled,
    Revoked,
}

impl From<u8> for RotKeyStatus {
    fn from(value: u8) -> Self {
        use RotKeyStatus::*;
        match value {
            0b00 => Invalid,
            0b01 => Enabled,
            0b10 | 0b11 => Revoked,
            _ => Invalid,
        }
    }
}

impl From<u32> for RotKeysStatus {
    fn from(value: u32) -> Self {
        let value = value as u8;
        let key_0_status = RotKeyStatus::from((value >> 0) & 0b11);
        let key_1_status = RotKeyStatus::from((value >> 2) & 0b11);
        let key_2_status = RotKeyStatus::from((value >> 4) & 0b11);
        let key_3_status = RotKeyStatus::from((value >> 6) & 0b11);
        Self { key_0_status, key_1_status, key_2_status, key_3_status }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum DebugSecurityPolicy {
    EnableWithDap,
    Disabled,
    Enabled,
}

impl DebugSecurityPolicy {
    fn fixed_bit(&self) -> u32 {
        use DebugSecurityPolicy::*;
        match *self {
            EnableWithDap => 0,
            _ => 1,
        }
    }
    fn enabled_bit(&self) -> u32 {
        use DebugSecurityPolicy::*;
        match *self {
            Enabled => 1,
            _ => 0,
        }
    }
}

impl From<[bool; 2]> for DebugSecurityPolicy {
    fn from(bits: [bool; 2]) -> Self {
        let [fix, set] = bits;
        use DebugSecurityPolicy::*;
        match (fix, set) {
            (false, _) => EnableWithDap,
            (true, false) => Disabled,
            (true, true) => Enabled,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct DebugSecurityPolicies {
    nonsecure_noninvasive: DebugSecurityPolicy,
    nonsecure_invasive: DebugSecurityPolicy,
    secure_noninvasive: DebugSecurityPolicy,
    secure_invasive: DebugSecurityPolicy,
    cm33_invasive: DebugSecurityPolicy,
    cm33_noninvasive: DebugSecurityPolicy,

    /// JTAG test access port
    jtag_tap: DebugSecurityPolicy,

    /// ISP boot command
    isp_boot_command: DebugSecurityPolicy,
    /// FA (fault analysis) command
    fault_analysis_command: DebugSecurityPolicy,

    /// enforce UUID match during debug authentication
    check_uuid: bool,
}

impl From<[u32; 2]> for DebugSecurityPolicies {
    fn from(value: [u32; 2]) -> Self {
        let [fix, set] = value;
        Self {
            nonsecure_noninvasive: DebugSecurityPolicy::from([
                ((fix >> 0) & 1) != 0,
                ((set >> 0) & 1) != 0,
            ]),
            nonsecure_invasive: DebugSecurityPolicy::from([
                ((fix >> 1) & 1) != 0,
                ((set >> 1) & 1) != 0,
            ]),
            secure_noninvasive: DebugSecurityPolicy::from([
                ((fix >> 2) & 1) != 0,
                ((set >> 2) & 1) != 0,
            ]),
            secure_invasive: DebugSecurityPolicy::from([
                ((fix >> 3) & 1) != 0,
                ((set >> 3) & 1) != 0,
            ]),
            jtag_tap: DebugSecurityPolicy::from([
                ((fix >> 4) & 1) != 0,
                ((set >> 4) & 1) != 0,
            ]),
            cm33_invasive: DebugSecurityPolicy::from([
                ((fix >> 5) & 1) != 0,
                ((set >> 5) & 1) != 0,
            ]),
            isp_boot_command: DebugSecurityPolicy::from([
                ((fix >> 6) & 1) != 0,
                ((set >> 6) & 1) != 0,
            ]),
            fault_analysis_command: DebugSecurityPolicy::from([
                ((fix >> 7) & 1) != 0,
                ((set >> 7) & 1) != 0,
            ]),
            cm33_noninvasive: DebugSecurityPolicy::from([
                ((fix >> 9) & 1) != 0,
                ((set >> 9) & 1) != 0,
            ]),
            check_uuid: ((fix >> 15) & 1) != 0,
        }
    }
}

impl Into<[u32; 2]> for DebugSecurityPolicies {
    fn into(self) -> [u32; 2] {
        let mut fixed: u32 = 0;
        let mut enabled: u32 = 0;

        fixed |= self.nonsecure_noninvasive.fixed_bit() << 0;
        enabled |= self.nonsecure_noninvasive.enabled_bit() << 0;

        fixed |= self.nonsecure_invasive.fixed_bit() << 1;
        enabled |= self.nonsecure_invasive.enabled_bit() << 1;

        fixed |= self.secure_noninvasive.fixed_bit() << 2;
        enabled |= self.secure_noninvasive.enabled_bit() << 2;

        fixed |= self.secure_invasive.fixed_bit() << 3;
        enabled |= self.secure_invasive.enabled_bit() << 3;

        fixed |= self.jtag_tap.fixed_bit() << 4;
        enabled |= self.jtag_tap.enabled_bit() << 4;

        fixed |= self.cm33_invasive.fixed_bit() << 5;
        enabled |= self.cm33_invasive.enabled_bit() << 5;

        fixed |= self.isp_boot_command.fixed_bit() << 6;
        enabled |= self.isp_boot_command.enabled_bit() << 6;

        fixed |= self.fault_analysis_command.fixed_bit() << 7;
        enabled |= self.fault_analysis_command.enabled_bit() << 7;

        fixed |= self.cm33_noninvasive.fixed_bit() << 9;
        enabled |= self.cm33_noninvasive.enabled_bit() << 9;


        fixed |= (self.check_uuid as u32) << 15;
        [fixed, enabled]
    }
}


fn parse_cfpa_page<CustomerData: CustomerDataCfpaRegion, VendorUsage: VendorUsageCfpaRegion>(input: &[u8])
    -> IResult<&[u8], CfpaPage<CustomerData, VendorUsage>>
{
    let (input, header) = le_u32(input)?;
    let (input, version) = le_u32(input)?;
    let (input, secure_firmware_version) = le_u32(input)?;
    let (input, nonsecure_firmware_version) = le_u32(input)?;
    let (input, image_key_revocation_id) = le_u32(input)?;

    // reserved
    let (input, _) = take!(input, 4)?;

    let (input, rot_keys_status) = le_u32(input)?;
    let (input, vendor_usage) = le_u32(input)?;
    let (input, dcfg_cc_socu_ns_pin) = le_u32(input)?;
    let (input, dcfg_cc_socu_ns_default) = le_u32(input)?;
    let (input, enable_fa) = le_u32(input)?;
    let (input, cmpa_prog_in_progress) = le_u32(input)?;

    let (input, prince_iv_code0) = le_u32(input)?;
    let (input, prince_iv_code1) = le_u32(input)?;
    let (input, prince_iv_code2) = le_u32(input)?;

    // reserved
    let (input, _) = take!(input, 10 * 4)?;

    let (input, customer_data) = take!(input, 56 * 4)?;

    let (input, sha256_hash) = take!(input, 32)?;

    let page = CfpaPage {
        header: Header(header),
        version: Version(version),
        secure_firmware_version: MonotonicCounter::from(secure_firmware_version),
        nonsecure_firmware_version: MonotonicCounter::from(nonsecure_firmware_version),
        image_key_revocation_id: MonotonicCounter::from(image_key_revocation_id),
        vendor_usage: VendorUsage::from(vendor_usage),
        rot_keys_status: RotKeysStatus::from(rot_keys_status),
        debug_settings: DebugSecurityPolicies::from([dcfg_cc_socu_ns_default, dcfg_cc_socu_ns_pin]),
        enable_fa_mode: enable_fa != 0,
        cmpa_prog_in_progress: CmpaProgInProgress(cmpa_prog_in_progress),
        prince_ivs: [
            PrinceIvCode(prince_iv_code0),
            PrinceIvCode(prince_iv_code1),
            PrinceIvCode(prince_iv_code2),
        ],
        customer_data: CustomerData::from(customer_data.try_into().unwrap()),
        sha256_hash: Sha256Hash(sha256_hash.try_into().unwrap()),
    };

    Ok((input, page))
}


impl<CustomerData, VendorUsage> core::convert::TryFrom<&[u8]> for CfpaPage<CustomerData, VendorUsage>
where
    CustomerData: CustomerDataCfpaRegion,
    VendorUsage: VendorUsageCfpaRegion,
{
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let (_input, page) = parse_cfpa_page(input).unwrap();
        Ok(page)
    }
}

impl<CustomerData, VendorUsage> core::convert::TryFrom<&[u8]> for Cmpa<CustomerData, VendorUsage>
where
    CustomerData: CustomerDataCmpaRegion,
    VendorUsage: VendorUsageCmpaRegion,
{
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let (_input, page) = parse_cmpa(input).unwrap();
        Ok(page)
    }
}
