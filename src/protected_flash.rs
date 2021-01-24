//! The protected flash area (PFR) as Rust types
//!
use core::convert::TryInto;
use core::fmt;
use std::io::Write as _;

use crate::util::{hex_serialize, hex_deserialize_256, is_default};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use nom::{
    IResult,
    number::complete::le_u32,
    take,
};

use serde_big_array::big_array;
big_array! {
    BigArray;
    +1192,
}

pub const FACTORY_SETTINGS_ADDRESS: usize = 0x9_E400;
pub const CUSTOMER_SETTINGS_SCRATCH_ADDRESS: usize = 0x9_DE00;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// For a graphical overview: <https://whimsical.com/lpc55-flash-memory-map-4eU3ei4wsqiAD7D2cAiv5s>
///
/// - customer page: one flash page (512B) of configuration data that may be updated during the device's
/// lifecycle via a scratch/ping/pong process
/// - factory page: one flash page (512B) of configuration data, to be set during manufacturing process
/// - keystore: three flash pages, technically considered part of the factory configuration data,
/// containing activation and key codes for the PUF keys.
pub struct ProtectedFlash {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub customer: CustomerSettingsArea,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub factory: FactorySettings,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub keystore: Keystore,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct FactorySettings<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: FactorySettingsCustomerData,
    VendorUsage: FactorySettingsVendorUsage,
{
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub boot_configuration: BootConfiguration,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub usb_id: UsbId,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub debug_settings: DebugSecurityPolicies,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub vendor_usage: VendorUsage,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub secure_boot_configuration: SecureBootConfiguration,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub prince_configuration: PrinceConfiguration,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub prince_subregions: [PrinceSubregion; 3],
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    #[serde(deserialize_with = "hex_deserialize_256")]
    /// Fingerprint of allowed root certificates for signed firmware update process.
    ///
    /// Called "ROTKH" for "root of trust key table hash" in vendor documentation.
    ///
    /// There can be up to four root certificate authorities; each have a "fingerprint" (cf.
    /// elsewhere), the fingerprint here is the SHA256 hash of the concatenation of these
    /// fingerprints. Due to this construction, each SB2.1 firmware container needs to contain
    /// all the root certificates (plus possibly a certificate chain to the authority actually
    /// signing the firmware).
    pub rot_fingerprint: Sha256Hash,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    /// 224 bytes that the customer can use.
    pub customer_data: CustomerData,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    pub sha256_hash: Sha256Hash,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// See `CustomerSettingsArea` documentation for how this part of the configuration is
/// used and updated by the ROM bootloader.
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct CustomerSettings<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: CustomerSettingsCustomerData,
    VendorUsage: CustomerSettingsVendorUsage,
{
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub header: Header,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// monotonic counter
    pub customer_version: MonotonicCounter,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// monotonic counter
    pub secure_firmware_version: MonotonicCounter,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// monotonic counter
    pub nonsecure_firmware_version: MonotonicCounter,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub image_key_revocation_id: MonotonicCounter,

    // following three have "upper16 bits are inverse of lower16 bits"
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub vendor_usage: VendorUsage,
    // pub rot_keys_status: [RotKeyStatus; 4],
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub rot_keys_status: RotKeysStatus,
    // UM 11126
    // 51.7.1: DCFG_CC = device configuration for credential constraints
    // 51.7.7: SOCU = System-on-Chip Usage
    // PIN = "pinned" or fixed
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub debug_settings: DebugSecurityPolicies,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub enable_fault_analysis_mode: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub factory_prog_in_progress: FactorySettingsProgInProgress,

    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub prince_ivs: [
        PrinceIvCode; 3],

    // customer_data: [u32; 4*14],  // or [u128, 14]
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    pub customer_data: CustomerData,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    pub sha256_hash: Sha256Hash,
}

impl CustomerSettings {
    pub fn valid_activation_code(&self) -> bool {
        self.header.0 == 0x95959595
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Type enabling `lpc55 configure factory-settings` to share config file with the secure/signed
/// firmware generation commands. Serializes `FactorySettings` with a `[factory-settings]` header.
pub struct WrappedFactorySettings<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: FactorySettingsCustomerData,
    VendorUsage: FactorySettingsVendorUsage,
{
    #[serde(skip_serializing_if = "is_default")]
    pub factory_settings: FactorySettings<CustomerData, VendorUsage>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Type enabling `lpc55 configure customer-settings` to share config file with the secure/signed
/// firmware generation commands. Serializes `CustomerSettings` with a `[customer-settings]` header.
pub struct WrappedCustomerSettings<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: CustomerSettingsCustomerData,
    VendorUsage: CustomerSettingsVendorUsage,
{
    #[serde(skip_serializing_if = "is_default")]
    pub customer_settings: CustomerSettings<CustomerData, VendorUsage>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeystoreHeader(pub u32);

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// Input to regenerate keys "stored" in the PUF.
///
/// TODO: split into
/// - key code valid (first four bytes)
/// - key parameters (user/generated, length, ...?)
/// - actual keycode = last 52 bytes
///
/// Empirically, these arrays start with either '59595959 01000002' for 16B keys,
/// or '59595959 00000004' for 32B keys.
///
/// A generated UDS key example seens in the wild starts with `59595959 010F0004`
/// however.
///
/// Presumably (entire paragraph is speculative), this is followed by 32B of input to be XOR'd or
/// whatnot with the 32B "fingerprint" derived from PUF "startup data" via error correction with
/// the "activation code" (and then truncated to key length). Which would leave 16B hash.
pub struct Keycode(
    #[serde(with = "BigArray")]
    [u8; 56]
);

impl Keycode {
    /// Not sure if this is true (in analogy with "header")
    pub fn valid(&self) -> bool {
        self.0[..4] == [0x59, 0x59, 0x59, 0x59]
    }

    // UM 11126 (rev2.1, 7.3.1, table 175) seems a bit incorrect and confusing here...
    pub fn generated_key(&self) -> bool {
        self.0[4] == 1
    }

    pub fn user_key(&self) -> bool {
        self.0[4] == 0
    }
}

impl Default for Keycode {
    fn default() -> Self {
        Keycode([0u8; 56])
    }
}

impl fmt::Debug for Keycode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes(&self.0, f)
    }
}

impl AsRef<[u8]> for Keycode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ActivationCode(
    #[serde(with = "BigArray")]
    [u8; 1192]
);

impl Default for ActivationCode {
    fn default() -> Self {
        ActivationCode([0u8; 1192])
    }
}

impl fmt::Debug for ActivationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes(&self.0, f)
    }
}

impl AsRef<[u8]> for ActivationCode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// All the keys :)
///
/// We "unroll" the prince_regions array to be able to serialize_with hex_serialize.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Keystore {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// The Excel spreadsheet says "Valid Key Sore Header : 0x95959595u".
    ///
    /// Empirically, this value 2509608341 appears as header in the PFR
    /// as soon as PUF is enrolled, regardless of number of key codes stored.
    ///
    /// UM 11126 says: "Marker. A value of 0x95959595 means that Activation code is valid."
    pub header: KeystoreHeader,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// Excel spreadsheet specifies this interpretation.
    ///
    /// Seems this can't be actually set anywhere.
    pub puf_discharge_time_milliseconds: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    /// 1192 bytes of data, generated when PUF is enrolled.
    pub activation_code: ActivationCode,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    /// KEK for secure boot, aka SBKEK.
    ///
    /// This is an actual "key encryption key". The SB2.1 container format uses two "random"
    /// firmware encryption and MAC keys, which are stored via AES keywrap with this SBKEK in the
    /// container.
    pub secure_boot_kek: Keycode,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    pub user_key: Keycode,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    /// Key intended for use with the "DICE" algorithm, which is a Microsoft standard to ensure
    /// devices and their firmware are authentic; based on symmetric cryptography.
    pub unique_device_secret: Keycode,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    /// Key used when PRINCE is activated for the first PRINCE region (first 256K flash)
    pub prince_region_0: Keycode,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    /// Key used when PRINCE is activated for the first PRINCE region (second 256K flash)
    pub prince_region_1: Keycode,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    #[serde(serialize_with = "hex_serialize")]
    /// Key used when PRINCE is activated for the first PRINCE region (last 128K flash, or more
    /// precisely, 119.5K -- excluding PFR itself)
    pub prince_region_2: Keycode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// This is incorrect. There's more in the NMPA spreadsheet section!
pub struct NxpArea {
    uuid: u128,
}

impl Keystore {
    pub fn to_bytes(&self) -> [u8; 3*512] {
        let mut buf = [0u8; 3*512];
        let mut cursor = buf.as_mut();
        cursor.write_all(&self.header.0.to_le_bytes()).ok();
        cursor.write_all(&self.puf_discharge_time_milliseconds.to_le_bytes()).ok();
        cursor.write_all(&self.activation_code.0).ok();
        cursor.write_all(&self.secure_boot_kek.0).ok();
        cursor.write_all(&self.user_key.0).ok();
        cursor.write_all(&self.unique_device_secret.0).ok();
        cursor.write_all(&self.prince_region_0.0).ok();
        cursor.write_all(&self.prince_region_1.0).ok();
        cursor.write_all(&self.prince_region_2.0).ok();
        assert!(cursor.is_empty());
        buf
    }
}

fn parse_keystore(input: &[u8]) -> IResult<&[u8], Keystore> {
    let (input, header) = le_u32(input)?;
    let (input, puf_discharge_time_milliseconds) = le_u32(input)?;
    let (input, activation_code) = take!(input, 1192)?;
    let (input, secure_boot_kek) = take!(input, 56)?;
    let (input, user_key) = take!(input, 56)?;
    let (input, unique_device_secret) = take!(input, 56)?;
    let (input, prince_region_0) = take!(input, 56)?;
    let (input, prince_region_1) = take!(input, 56)?;
    let (input, prince_region_2) = take!(input, 56)?;

    let keystore = Keystore {
        header: KeystoreHeader(header),
        puf_discharge_time_milliseconds,
        activation_code: ActivationCode(activation_code.try_into().unwrap()),
        secure_boot_kek: Keycode(secure_boot_kek.try_into().unwrap()),
        user_key: Keycode(user_key.try_into().unwrap()),
        unique_device_secret: Keycode(unique_device_secret.try_into().unwrap()),
        prince_region_0: Keycode(prince_region_0.try_into().unwrap()),
        prince_region_1: Keycode(prince_region_1.try_into().unwrap()),
        prince_region_2: Keycode(prince_region_2.try_into().unwrap()),
    };

    Ok((input, keystore))
}

impl<CustomerData, VendorUsage> FactorySettings<CustomerData, VendorUsage>
where
    CustomerData: FactorySettingsCustomerData,
    VendorUsage: FactorySettingsVendorUsage,
{
    pub fn to_bytes(&self) -> anyhow::Result<[u8; 512]> {
        let mut buf = [0u8; 512];
        let mut cursor = buf.as_mut();

        cursor.write_all(&u32::from(self.boot_configuration).to_le_bytes())?;
        cursor.write_all(&[0u8; 4])?;
        cursor.write_all(&self.usb_id.vid.to_le_bytes())?;
        cursor.write_all(&self.usb_id.pid.to_le_bytes())?;
        cursor.write_all(&[0u8; 4])?;

        // TODO: check/fix
        // let debug_settings: [u32; 2] = self.debug_settings.into();
        let debug_settings: [u32; 2] = [0; 2];
        cursor.write_all(&debug_settings[0].to_le_bytes())?;
        cursor.write_all(&debug_settings[1].to_le_bytes())?;

        cursor.write_all(&self.vendor_usage.into().to_le_bytes())?;
        cursor.write_all(&u32::from(self.secure_boot_configuration).to_le_bytes())?;
        cursor.write_all(&u32::from(self.prince_configuration).to_le_bytes())?;
        cursor.write_all(&self.prince_subregions[0].bits.to_le_bytes())?;
        cursor.write_all(&self.prince_subregions[1].bits.to_le_bytes())?;
        cursor.write_all(&self.prince_subregions[2].bits.to_le_bytes())?;
        cursor.write_all(&[0u8; 32])?;
        cursor.write_all(&self.rot_fingerprint.0)?;
        cursor.write_all(&[0u8; 144])?;
        cursor.write_all(self.customer_data.as_ref())?;
        assert_eq!(cursor.len(), 32);

        Ok(buf)
    }

    pub fn to_bytes_setting_hash(&mut self) -> anyhow::Result<[u8; 512]> {
        let mut buf = self.to_bytes()?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&buf[..480]);
        self.sha256_hash = Sha256Hash(hasher.finalize().try_into().unwrap());

        let mut cursor = buf[480..].as_mut();
        cursor.write_all(&self.sha256_hash.0).ok();
        assert!(cursor.is_empty());
        Ok(buf)
    }

}

fn parse_factory<CustomerData: FactorySettingsCustomerData, VendorUsage: FactorySettingsVendorUsage>(input: &[u8])
    -> IResult<&[u8], FactorySettings<CustomerData, VendorUsage>>
{
    let (input, boot_cfg) = le_u32(input)?;
    let (input, _spi_flash_cfg) = le_u32(input)?;
    assert_eq!(_spi_flash_cfg, 0);
    let (input, usb_id) = le_u32(input)?;
    let (input, _sdio_cfg) = le_u32(input)?;
    assert_eq!(_sdio_cfg, 0);
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

    let (input, rot_fingerprint) = take!(input, 32)?;

    // reserved
    let (input, _) = take!(input, 9 * 4 * 4)?;

    let (input, customer_data) = take!(input, 14 * 4 * 4)?;

    let (input, sha256_hash) = take!(input, 32)?;

    let factory = FactorySettings {
        boot_configuration: BootConfiguration::from(boot_cfg),
        usb_id: UsbId::from(usb_id),
        debug_settings: DebugSecurityPolicies::from([cc_socu_default, cc_socu_pin]),
        vendor_usage: VendorUsage::from(vendor_usage),
        secure_boot_configuration: SecureBootConfiguration::from(secure_boot_cfg),
        prince_configuration: PrinceConfiguration::from(prince_cfg),
        prince_subregions: [
            PrinceSubregion::from_bits_truncate(prince_sr_0),
            PrinceSubregion::from_bits_truncate(prince_sr_1),
            PrinceSubregion::from_bits_truncate(prince_sr_2),
        ],
        rot_fingerprint: Sha256Hash(rot_fingerprint.try_into().unwrap()),
        customer_data: CustomerData::from(customer_data.try_into().unwrap()),
        sha256_hash: Sha256Hash(sha256_hash.try_into().unwrap()),
    };

    Ok((input, factory))
}


#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum BootSpeed {
    Nxp = 0,
    #[serde(rename = "48Mhz")]
    Fro48 = 1,
    #[serde(rename = "96Mhz")]
    Fro96 = 2,
    Reserved = 3,
}

impl Default for BootSpeed {
    fn default() -> Self {
        Self::Nxp
    }
}

impl From<u8> for BootSpeed {
    fn from(value: u8) -> Self {
        use BootSpeed::*;
        match value {
            0b00 => Nxp,
            0b01 => Fro48,
            0b10 => Fro96,
            0b11 | _ => Reserved,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum IspMode {
    Auto,
    Usb,
    Uart,
    Spi,
    I2c,
    FallthroughDisabled,
    Reserved(u8),
}

impl Default for IspMode {
    fn default() -> Self {
        Self::Auto
    }
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

impl From<IspMode> for u8 {
    fn from(mode: IspMode) -> u8 {
        use IspMode::*;
        match mode {
            Auto => 0,
            Usb => 1,
            Uart => 2,
            Spi => 3,
            I2c => 4,
            FallthroughDisabled => 5,
            Reserved(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BootConfiguration {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub failure_port: u8,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub failure_pin: u8,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub speed: BootSpeed,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub mode: IspMode,
}

impl From<u32> for BootConfiguration {
    fn from(word: u32) -> Self {
        Self {
            failure_port: ((word >> 24) & 0b11) as u8,
            failure_pin: ((word >> 26) & 0b11111) as u8,
            speed: BootSpeed::from(((word >> 7) & 0b11) as u8),
            mode: IspMode::from(((word >> 4) & 0b111) as u8),
        }
    }
}

impl From<BootConfiguration> for u32 {
    fn from(cfg: BootConfiguration) -> u32 {
        let mut word = 0u32;

        word |= ((cfg.failure_port & 0b11) as u32) << 24;
        word |= ((cfg.failure_pin & 0b11111) as u32) << 26;
        word |= (cfg.speed as u8 as u32) << 7;
        word |= (u8::from(cfg.mode) as u32) << 3;

        word

    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// The PID/VID pair of the bootloader can be set arbitrarily, the default
/// of `1fc9:0021` is used if the values zero are not changed.
pub struct UsbId {
    pub vid: u16,
    pub pid: u16,
}

impl Default for UsbId {
    fn default() -> Self {
        // Self { vid: 0x1fc9, pid: 0x0021 }
        Self { vid: 0, pid: 0 }
    }
}

impl From<u32> for UsbId {
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

fn boolmulti(value: bool) -> u32 {
    match value {
        false => 0,
        true => 0b11,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum TrustzoneMode {
    FromImageHeader = 0b00,
    DisabledBootToNonsecure = 0b01,
    EnabledBootToSecure = 0b10,
    // what is this?
    PresetTrustzoneCheckerFromImageHeader = 0b11,
}

impl Default for TrustzoneMode {
    fn default() -> Self {
        Self::FromImageHeader
    }
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SecureBootConfiguration {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub secure_boot_enabled: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub puf_enrollment_disabled: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub puf_keycode_generation_disabled: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub trustzone_mode: TrustzoneMode,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// For this DICE stuff, see also https://www.microsoft.com/en-us/research/project/dice-device-identifier-composition-engine/
    /// and the actual standard https://trustedcomputinggroup.org/resource/hardware-requirements-for-a-device-identifier-composition-engine/
    pub dice_computation_disabled: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub include_factory_area_in_dice_computation: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub include_nxp_area_in_dice_computation: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub include_security_epoch_area_in_dice_computation: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub use_rsa4096_keys: bool,
}

impl From<u32> for SecureBootConfiguration {
    fn from(word: u32) -> Self {
        Self {
            secure_boot_enabled: multibool((word >> 30) & 0b11),
            puf_enrollment_disabled: multibool((word >> 12) & 0b11),
            puf_keycode_generation_disabled: multibool((word >> 10) & 0b11),
            trustzone_mode: TrustzoneMode::from((word >> 8) & 0b11),
            dice_computation_disabled: multibool((word >> 6) & 0b11),
            // cf. UM 11126, Ch. 7, table 177
            include_security_epoch_area_in_dice_computation: multibool((word >> 14) & 0b11),
            include_factory_area_in_dice_computation: multibool((word >> 4) & 0b11),
            include_nxp_area_in_dice_computation: multibool((word >> 2) & 0b11),
            use_rsa4096_keys: multibool((word >> 0) & 0b11),
        }
    }
}

impl From<SecureBootConfiguration> for u32 {
    fn from(cfg: SecureBootConfiguration) -> u32 {
        let mut word = 0u32;
        word |= boolmulti(cfg.secure_boot_enabled) << 30;
        word |= boolmulti(cfg.puf_enrollment_disabled) << 12;
        word |= boolmulti(cfg.puf_keycode_generation_disabled) << 10;
        word |= (cfg.trustzone_mode as u8 as u32) << 8;
        word |= boolmulti(cfg.dice_computation_disabled) << 6;
        word |= boolmulti(cfg.include_security_epoch_area_in_dice_computation) << 14;
        word |= boolmulti(cfg.include_factory_area_in_dice_computation) << 4;
        word |= boolmulti(cfg.include_nxp_area_in_dice_computation) << 2;
        word |= boolmulti(cfg.use_rsa4096_keys) << 0;
        word
    }
}

impl From<PrinceConfiguration> for u32 {
    fn from(cfg: PrinceConfiguration) -> u32 {
        let mut word = 0u32;
        word |= boolmulti(cfg.erase_checks[0]) << 28;
        word |= boolmulti(cfg.erase_checks[0]) << 26;
        word |= boolmulti(cfg.erase_checks[0]) << 24;
        word |= boolmulti(cfg.locked[0]) << 20;
        word |= boolmulti(cfg.locked[0]) << 18;
        word |= boolmulti(cfg.locked[0]) << 16;
        word |= (cfg.addresses[0] as u32) << 8;
        word |= (cfg.addresses[1] as u32) << 4;
        word |= (cfg.addresses[2] as u32) << 0;
        word
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PrinceConfiguration {
    pub erase_checks: [bool; 3],
    pub locked: [bool; 3],
    pub addresses: [u8; 3],
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

// #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
// // UM, Chap. 7
// // Each bit in this field enables a sub-region of crypto region x at offset
// // 8kB*n, where n is the bit number. A 0 in bit n bit means encryption and
// // decryption of data associated with sub-region n is disabled. A 1 in bit n
// // means that data written to sub-region n during flash programming when
// // ENC_ENABLE.EN = 1 will be encrypted, and flash reads from
// // sub-region n will be decrypted using the PRINCE.
// pub struct PrinceSubregion(u32);
bitflags::bitflags! {
    #[derive(Default, Deserialize, Serialize)]
    // #[serde(transparent)]
    pub struct PrinceSubregion: u32 {
        const REGION_00 = 1 << 0;
        const REGION_01 = 1 << 1;
        const REGION_02 = 1 << 2;
        const REGION_03 = 1 << 3;
        const REGION_04 = 1 << 4;
        const REGION_05 = 1 << 5;
        const REGION_06 = 1 << 6;
        const REGION_07 = 1 << 7;
        const REGION_08 = 1 << 8;
        const REGION_09 = 1 << 9;
        const REGION_10 = 1 << 10;
        const REGION_11 = 1 << 11;
        const REGION_12 = 1 << 12;
        const REGION_13 = 1 << 13;
        const REGION_14 = 1 << 14;
        const REGION_15 = 1 << 15;
        const REGION_16 = 1 << 16;
        const REGION_17 = 1 << 17;
        const REGION_18 = 1 << 18;
        const REGION_19 = 1 << 19;
        const REGION_20 = 1 << 20;
        const REGION_21 = 1 << 21;
        const REGION_22 = 1 << 22;
        const REGION_23 = 1 << 23;
        const REGION_24 = 1 << 24;
        const REGION_25 = 1 << 25;
        const REGION_26 = 1 << 26;
        const REGION_27 = 1 << 27;
        const REGION_28 = 1 << 28;
        const REGION_29 = 1 << 29;
        const REGION_30 = 1 << 30;
        const REGION_31 = 1 << 31;
    }
}

impl core::convert::TryFrom<&[u8]> for ProtectedFlash {
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let factory = FactorySettings::try_from(&input[3*512..4*512]).unwrap();
        let customer = CustomerSettingsArea::try_from(&input[..3*512]).unwrap();
        let keystore = Keystore::try_from(&input[4*512..7*512]).unwrap();

        let pfr = ProtectedFlash { customer, factory, keystore };

        Ok(pfr)
    }
}

fn format_bytes(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    // let l = bytes.len();
    let empty = bytes.iter().all(|&byte| byte == 0);
    if empty {
        // return f.write_fmt(format_args!("<all zero>"));
        return f.write_fmt(format_args!("∅"));
    }

    for byte in bytes.iter() {
        f.write_fmt(format_args!("{:02X} ", byte))?;
    }
    Ok(())
    // let info = if empty { "empty" } else { "non-empty" };

    // f.write_fmt(format_args!(
    //     "'{:02x} {:02x} {:02x} (...) {:02x} {:02x} {:02x} ({})'",
    //     bytes[0], bytes[1], bytes[3],
    //     bytes[l-3], bytes[l-2], bytes[l-1],
    //     info,
    // ))
}

pub trait CustomerSettingsCustomerData: AsRef<[u8]> + fmt::Debug + Default + From<[u8; 14*4*4]> + PartialEq {}
pub trait FactorySettingsCustomerData: AsRef<[u8]> + fmt::Debug + Default + From<[u8; 14*4*4]> + PartialEq {}

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RawCustomerData(
    #[serde(with = "BigArray")]
    [u8; 4*4*14]
);

impl AsRef<[u8]> for RawCustomerData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for RawCustomerData {
    fn default() -> Self {
        RawCustomerData([0u8; 224])
    }
}

impl fmt::Debug for RawCustomerData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes(&self.0, f)
    }
}

impl From<[u8; 14*4*4]> for RawCustomerData {
    fn from(bytes: [u8; 224]) -> Self {
        Self(bytes)
    }
}

impl CustomerSettingsCustomerData for RawCustomerData {}
impl FactorySettingsCustomerData for RawCustomerData {}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// This is a bit of an interesting construction.
///
/// The scratch page "remains outside the protected region", the intent is that the application
/// updates this (in NXP's view, by calling bootloader API), and then resets the core.
///
/// During startup, bootloader selects one of ping or pong page, depending on which has higher
/// "version" field. If scratch page has even higher "version", the bootloader erases the older
/// of ping/pong and overwrites with scratch.
pub struct CustomerSettingsArea<CustomerData=RawCustomerData, VendorUsage=RawVendorUsage>
where
    CustomerData: CustomerSettingsCustomerData,
    VendorUsage: CustomerSettingsVendorUsage,
{
    pub scratch: CustomerSettings<CustomerData, VendorUsage>,
    pub ping: CustomerSettings<CustomerData, VendorUsage>,
    pub pong: CustomerSettings<CustomerData, VendorUsage>,
}

impl core::convert::TryFrom<&[u8]> for CustomerSettingsArea {
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let scratch = CustomerSettings::try_from(&input[..512]).unwrap();
        let ping = CustomerSettings::try_from(&input[512..2*512]).unwrap();
        let pong = CustomerSettings::try_from(&input[2*512..3*512]).unwrap();

        let customer_settings = CustomerSettingsArea { scratch, ping, pong };

        Ok(customer_settings)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Header(u32);

// #[derive(Debug)]
// pub struct Version(u32);

pub trait CustomerSettingsVendorUsage: Clone + Copy + fmt::Debug + Default + From<u32> + Into<u32> + PartialEq {}
pub trait FactorySettingsVendorUsage: Clone + Copy + fmt::Debug + Default + From<u32> + Into<u32> + PartialEq {}
#[derive(Clone, Copy, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RawVendorUsage(u32);

impl fmt::Debug for RawVendorUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RawVendorUsage").field(&self.0).finish()
    }
}

impl From<RawVendorUsage> for u32 {
    fn from(usage: RawVendorUsage) -> u32 {
        usage.0
    }
}

impl From<u32> for RawVendorUsage {
    fn from(word: u32) -> Self {
        Self(word)
    }
}

impl CustomerSettingsVendorUsage for RawVendorUsage {}
impl FactorySettingsVendorUsage for RawVendorUsage {}

#[derive(Clone, Copy, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Sha256Hash(pub [u8; 32]);
impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes(&self.0, f)
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Sha256Hash {
    fn from(array: [u8; 32]) -> Self {
        Sha256Hash(array)
    }
}

/// CMPA Page programming on going. This field shall be set to 0x5CC55AA5 in the active CFPA page each time CMPA page programming is going on. It shall always be set to 0x00000000 in the CFPA scratch area.
#[derive(Clone, Copy, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FactorySettingsProgInProgress(u32);

impl fmt::Debug for FactorySettingsProgInProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            // 0x00000000 => f.write_str("empty"),
            0x0000_0000 => f.write_fmt(format_args!("empty (0x{:x})", 0)),
            // 1556437669
            0x5CC5_5AA5 => f.write_str("CMPA page programming ongoing"),
            value => f.write_fmt(format_args!("unknown value {:x}", value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RotKeysStatus([RotKeyStatus; 4]);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// Generated and used only by bootloader.
///
/// Not to be modified by user.
pub struct PrinceIvCode(
    #[serde(with = "BigArray")]
    [u8; 56]
);

impl Default for PrinceIvCode {
    fn default() -> Self {
        PrinceIvCode([0u8; 56])
    }
}


#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum RotKeyStatus {
    Invalid = 0,
    Enabled = 1,
    Revoked = 3,
}

impl Default for RotKeyStatus {
    fn default() -> Self {
        Self::Invalid
    }
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

impl From<RotKeysStatus> for u32 {
    fn from(statii: RotKeysStatus) -> u32 {
        let mut value: u32 = 0;
        for (i, status) in statii.0.iter().enumerate() {
            value += (*status as u8 as u32) << (2*i);
        }
        value
    }
}

impl From<u32> for RotKeysStatus {
    fn from(value: u32) -> Self {
        let value = value as u8;
        let key_0_status = RotKeyStatus::from((value >> 0) & 0b11);
        let key_1_status = RotKeyStatus::from((value >> 2) & 0b11);
        let key_2_status = RotKeyStatus::from((value >> 4) & 0b11);
        let key_3_status = RotKeyStatus::from((value >> 6) & 0b11);
        Self([key_0_status, key_1_status, key_2_status, key_3_status])
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,Serialize)]
pub enum DebugSecurityPolicy {
    EnableWithDap,
    Disabled,
    Enabled,
}

impl Default for DebugSecurityPolicy {
    fn default() -> Self {
        Self::EnableWithDap
    }
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DebugSecurityPolicies {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub nonsecure_noninvasive: DebugSecurityPolicy,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub nonsecure_invasive: DebugSecurityPolicy,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub secure_noninvasive: DebugSecurityPolicy,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub secure_invasive: DebugSecurityPolicy,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub cm33_invasive: DebugSecurityPolicy,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub cm33_noninvasive: DebugSecurityPolicy,

    /// JTAG test access port
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub jtag_tap: DebugSecurityPolicy,

    /// ISP boot command
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub isp_boot_command: DebugSecurityPolicy,
    /// FA (fault analysis) command
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub fault_analysis_command: DebugSecurityPolicy,

    /// enforce UUID match during debug authentication
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub check_uuid: bool,
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

impl From<DebugSecurityPolicies> for [u32; 2] {
    fn from(policies: DebugSecurityPolicies) -> [u32; 2] {
        let mut fixed: u32 = 0;
        let mut enabled: u32 = 0;

        fixed |= policies.nonsecure_noninvasive.fixed_bit() << 0;
        enabled |= policies.nonsecure_noninvasive.enabled_bit() << 0;

        fixed |= policies.nonsecure_invasive.fixed_bit() << 1;
        enabled |= policies.nonsecure_invasive.enabled_bit() << 1;

        fixed |= policies.secure_noninvasive.fixed_bit() << 2;
        enabled |= policies.secure_noninvasive.enabled_bit() << 2;

        fixed |= policies.secure_invasive.fixed_bit() << 3;
        enabled |= policies.secure_invasive.enabled_bit() << 3;

        fixed |= policies.jtag_tap.fixed_bit() << 4;
        enabled |= policies.jtag_tap.enabled_bit() << 4;

        fixed |= policies.cm33_invasive.fixed_bit() << 5;
        enabled |= policies.cm33_invasive.enabled_bit() << 5;

        fixed |= policies.isp_boot_command.fixed_bit() << 6;
        enabled |= policies.isp_boot_command.enabled_bit() << 6;

        fixed |= policies.fault_analysis_command.fixed_bit() << 7;
        enabled |= policies.fault_analysis_command.enabled_bit() << 7;

        fixed |= policies.cm33_noninvasive.fixed_bit() << 9;
        enabled |= policies.cm33_noninvasive.enabled_bit() << 9;

        fixed |= (policies.check_uuid as u32) << 15;

        // "Inverse value of [15:0]"
        fixed |= !(fixed << 16);
        enabled |= !(fixed << 16);

        [fixed, enabled]
    }
}

impl<CustomerData, VendorUsage> CustomerSettings<CustomerData, VendorUsage>
where
    CustomerData: CustomerSettingsCustomerData,
    VendorUsage: CustomerSettingsVendorUsage,
{
    pub fn to_bytes(&self) -> anyhow::Result<[u8; 512]> {

        let mut buf = [0u8; 512];
        let mut cursor = buf.as_mut();

        cursor.write_all(&self.header.0.to_le_bytes())?;
        cursor.write_all(&self.customer_version.0.to_le_bytes())?;
        cursor.write_all(&self.secure_firmware_version.0.to_le_bytes())?;
        cursor.write_all(&self.nonsecure_firmware_version.0.to_le_bytes())?;
        cursor.write_all(&self.image_key_revocation_id.0.to_le_bytes())?;

        // reserved
        cursor.write_all(&[0u8; 4])?;

        cursor.write_all(&u32::from(self.rot_keys_status).to_le_bytes())?;
        cursor.write_all(&self.vendor_usage.into().to_le_bytes())?;

        // TODO: check/fix
        // let debug_settings: [u32; 2] = self.debug_settings.into();
        let debug_settings: [u32; 2] = [0; 2];
        cursor.write_all(&debug_settings[0].to_le_bytes())?;
        cursor.write_all(&debug_settings[1].to_le_bytes())?;

        let enable_fa_mode: u32 = match self.enable_fault_analysis_mode {
            true => 0xC33C_A55A,
            false => 0,
        };
        cursor.write_all(&enable_fa_mode.to_le_bytes())?;

        // factory_prog
        // "CMPA Page programming on going. This field shall be set to 0x5CC55AA5 in the active
        // CFPA page each time CMPA page programming is going on. It shall always be set to
        // 0x00000000 in the CFPA scratch area."
        cursor.write_all(&[0u8; 4])?;

        cursor.write_all(&self.prince_ivs[0].0)?;
        cursor.write_all(&self.prince_ivs[1].0)?;
        cursor.write_all(&self.prince_ivs[2].0)?;

        // reserved
        cursor.write_all(&[0u8; 40])?;

        cursor.write_all(self.customer_data.as_ref())?;

        assert_eq!(cursor.len(), 32);

        Ok(buf)
    }

    pub fn to_bytes_setting_hash(&mut self) -> anyhow::Result<[u8; 512]> {
        let mut buf = self.to_bytes()?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&buf[..480]);
        self.sha256_hash = Sha256Hash(hasher.finalize().try_into().unwrap());

        let mut cursor = buf[480..].as_mut();
        cursor.write_all(&self.sha256_hash.0).ok();
        assert!(cursor.is_empty());
        Ok(buf)
    }

}

fn parse_customer_page<CustomerData: CustomerSettingsCustomerData, VendorUsage: CustomerSettingsVendorUsage>(input: &[u8])
    -> IResult<&[u8], CustomerSettings<CustomerData, VendorUsage>>
{
    assert!(input.len() == 512);
    let (input, header) = le_u32(input)?;
    let (input, customer_version) = le_u32(input)?;
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
    let (input, factory_prog_in_progress) = le_u32(input)?;

    let (input, prince_iv_code0) = take!(input, 14*4)?;
    debug!("prince IV code 0 = {}", hex_str!(prince_iv_code0));
    let (input, prince_iv_code1) = take!(input, 14*4)?;
    let (input, prince_iv_code2) = take!(input, 14*4)?;

    // reserved
    let (input, _reserved) = take!(input, 10 * 4)?;
    debug!("reserved raw = {}", hex_str!(_reserved));

    let (input, customer_data) = take!(input, 56 * 4)?;
    debug!("customer_data all zero = {}", customer_data.iter().all(|x| *x == 0));
    debug!("customer_data raw = {}", hex_str!(customer_data));

    let (input, sha256_hash) = take!(input, 32)?;

    assert!(input.is_empty());
    let page = CustomerSettings {
        header: Header(header),
        customer_version: MonotonicCounter::from(customer_version),
        secure_firmware_version: MonotonicCounter::from(secure_firmware_version),
        nonsecure_firmware_version: MonotonicCounter::from(nonsecure_firmware_version),
        image_key_revocation_id: MonotonicCounter::from(image_key_revocation_id),
        vendor_usage: VendorUsage::from(vendor_usage),
        rot_keys_status: RotKeysStatus::from(rot_keys_status),
        debug_settings: DebugSecurityPolicies::from([dcfg_cc_socu_ns_default, dcfg_cc_socu_ns_pin]),
        enable_fault_analysis_mode: enable_fa != 0,
        factory_prog_in_progress: FactorySettingsProgInProgress(factory_prog_in_progress),
        prince_ivs: [
            PrinceIvCode(prince_iv_code0.try_into().unwrap()),
            PrinceIvCode(prince_iv_code1.try_into().unwrap()),
            PrinceIvCode(prince_iv_code2.try_into().unwrap()),
        ],
        customer_data: CustomerData::from(customer_data.try_into().unwrap()),
        sha256_hash: Sha256Hash(sha256_hash.try_into().unwrap()),
    };

    Ok((input, page))
}


impl<CustomerData, VendorUsage> core::convert::TryFrom<&[u8]> for CustomerSettings<CustomerData, VendorUsage>
where
    CustomerData: CustomerSettingsCustomerData,
    VendorUsage: CustomerSettingsVendorUsage,
{
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let (_input, page) = parse_customer_page(input).unwrap();
        Ok(page)
    }
}

impl<CustomerData, VendorUsage> core::convert::TryFrom<&[u8]> for FactorySettings<CustomerData, VendorUsage>
where
    CustomerData: FactorySettingsCustomerData,
    VendorUsage: FactorySettingsVendorUsage,
{
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let (_input, page) = parse_factory(input).unwrap();
        Ok(page)
    }
}

impl core::convert::TryFrom<&[u8]> for Keystore {
    type Error = ();
    fn try_from(input: &[u8]) -> ::std::result::Result<Self, Self::Error> {
        let (_input, keystore) = parse_keystore(input).unwrap();
        Ok(keystore)
    }
}
