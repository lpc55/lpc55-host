use nom::{
    IResult,
    number::complete::le_u32,
    named, take,
};

#[derive(Debug)]
pub struct Header(u32);

#[derive(Debug)]
pub struct Version(u32);

#[derive(Debug)]
pub struct VendorUsage(u32);

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
        match *self {
            EnableWithDap => 0,
            _ => 1,
        }
    }
    fn enabled_bit(&self) -> u32 {
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



// #[derive(Debug)]
// pub struct DeviceConfigurationForCredentialConstraints

#[derive(Debug)]
pub struct Cfpa {
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
    cmpa_prog_in_progress: u32,

    prince_ivs: [PrinceIvCode; 3],

    customer_defined: [u32; 4*14],  // or [u128, 14]
    sha256_hash: [u32; 8],
}

fn parse_cfpa(input: &[u8]) -> IResult<&[u8], Cfpa> {
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

    let (input, _) = take!(input, 4)?;

    let (input, prince_iv_code0) = le_u32(input)?;
    let (input, prince_iv_code1) = le_u32(input)?;
    let (input, prince_iv_code2) = le_u32(input)?;

    let (input, _) = take!(input, 40)?;

    let (input, customer_data) = le_u32(input)?;
    let (input, _) = take!(input, 224)?;

    // let (input, sha256) = le_u32(input)?;
    let (input, _) = take!(input, 32)?;

    let cfpa = Cfpa {
        header: Header(header),
        version: Version(header),
        secure_firmware_version: MonotonicCounter::from(secure_firmware_version),
        nonsecure_firmware_version: MonotonicCounter::from(nonsecure_firmware_version),
        image_key_revocation_id: MonotonicCounter::from(image_key_revocation_id),
        vendor_usage: VendorUsage(vendor_usage),
        rot_keys_status: RotKeysStatus::from(rot_keys_status),
        debug_settings: DebugSecurityPolicies::from([dcfg_cc_socu_ns_default, dcfg_cc_socu_ns_pin]),
        enable_fa_mode: enable_fa != 0,
        cmpa_prog_in_progress,
        prince_ivs: [
            PrinceIvCode(prince_iv_code0),
            PrinceIvCode(prince_iv_code1),
            PrinceIvCode(prince_iv_code2),
        ],
        customer_defined: [0u32; 56],
        sha256_hash: Default::default(),
    };

    Ok((input, cfpa))
}

impl core::convert::TryFrom<&[u8; 512]> for Cfpa {
    type Error = ();
    fn try_from(input: &[u8; 512]) -> ::std::result::Result<Self, Self::Error> {
        let (input, cfpa) = parse_cfpa(&input[..]).unwrap();
        Ok(cfpa)

        // todo!();
        // do_parse!(input,
        // );
    }
}
