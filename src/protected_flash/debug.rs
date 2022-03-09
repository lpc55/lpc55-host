// https://www.nxp.com/docs/en/application-note/AN13037.pdf

use serde::{Deserialize, Serialize};

use crate::util::is_default;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// Wrapper around the detailed debug access settings,
/// allowing to completely enable or disable with ease.
///
/// Use the custom variant for more detail.
pub enum DebugAccess {
    /// The state of an empty key (all four relevant words are all-zero)
    ///
    /// It seems that this state has the same effect as `Enabled`,
    /// if not please open a GitHub issue!
    Default,
    /// Debugging access is not possible
    Disabled,
    /// Debugging access is possible
    Enabled,
    /// Debugger must present a Debug Credential (this functionality
    /// is not currently implemented or further exposed).
    Authenticate,
    /// "Bring your own settings"
    Custom(DebugSettings),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// Controls access of debuggers to specific subsystems.
///
/// To understand if access is possible:
/// - factory + customer setting: Enabled -> yes
/// - factor + customer set to Enabled or Authenticate -> need a prepared debug certificate
///   (this is not implemented in this library)
/// - any setting Illegal => device may lock up
/// - any setting Disabled => access not possible!!
///
/// Peculiarities to be aware of:
/// - Factory settings (`CC_SOCU_PIN`, `CC_SOCU_DFLT`) can be made stricter, but not relaxed,
///   using customer settings (`DCFG_CC_SOCU_NS_PIN`, `DCFG_CC_SOCU_NS_DFLT`)
/// - As long as the factory page is not sealed, the setting can be changed there.
/// - To change settings in the customer page, the ping/pong dance must be done.
/// - The enabled bit ("DFLT") determines which setting is potentially in effect
/// - The fixed bit ("PIN") determines whether a debugger may activate the potentially
///   effective settings (by presenting a Debug Authentication certificate)
/// - The non-fixed enabled setting is illegal.
/// - All bits are written in the lower half-word, and must be also written in inverted
///   form in the upper half-word.
/// - Except, it seems, the default / empty setting, where both PIN and DFLT words are all zero.
///
/// In this implementation, we disregard customer settings from configuration files,
/// enforcing that only the firmware changes them.
///
/// TODO: We could also model the factory default, where the entire word is zeros.
/// This would need some special handling + research.
pub enum DebugSetting {
    /// Default state at startup. Will only be accepted when writing to
    /// factory settings when *all* settings are default.
    Default,
    /// Disabled at startup, debugging not possible
    Disabled,
    /// Debugging enabled at startup (debugger can't turn off).
    /// "Access to the sub-domain is always enabled."
    Enabled,
    // /// Enabled the policy, but it could be changed by authenticated debugger
    /// According to UM 11126, 51.7.14, Table 1064:
    /// "Illegal setting. Part may lock-up if this setting is selected."
    Illegal,
    /// Debugging disabled at startup, only authenticated debugger can access
    Authenticate,
}

impl Default for DebugAccess {
    /// Set to default, so that `lpc55 factory-settings` does not
    /// turn off debugging on an otherwise empty key, unless explicitly
    /// configured to be turned off.
    fn default() -> Self {
        Self::Default
    }
}

impl Default for DebugSetting {
    /// Set to enabled, so that `lpc55 factory-settings` does not
    /// turn off debugging on an otherwise empty key, unless explicitly
    /// configured to be turned off.
    ///
    /// It might be possible to set the default to `Self::Default` here,
    /// if we research whether its valid for some settings to stay
    /// 0 in both bits and also in the "inverted" section.
    fn default() -> Self {
        Self::Enabled
    }
}

impl DebugSetting {
    /// Called `PIN` by NXP, e.g in UM 11126, 51.7.14
    ///
    /// The interpretation is that the setting in the "enabled"
    /// bit can not be changed by the debugger (i.e. it can
    /// not enabled debugging by providing an appropriate Debug
    /// Credential (DC)).
    ///
    /// In their words:
    /// "A bitmask that specifies which debug domains are predetermined
    /// by device configuration."
    fn fixed_bit(&self) -> u32 {
        use DebugSetting::*;
        match *self {
            Authenticate | Default | Illegal => 0,
            Disabled | Enabled => 1,
        }
    }
    /// Called `DFLT` by NXP, e.g in UM 11126, 51.7.14
    ///
    /// The setting that is applied during startup.
    ///
    /// In their words:
    /// "Provides the final access level for those bits that the SOCU_PIN
    /// field indicated are predetermined by device configuration."
    ///
    /// It seems that the meaning of this bit is incorrectly used
    /// for the enabled and disabled states in Table 1064 of that section.
    /// And indeed, AN13037 confirms this.
    fn enabled_bit(&self) -> u32 {
        use DebugSetting::*;
        match *self {
            Disabled | Default | Authenticate => 0,
            Enabled | Illegal => 1,
        }
    }
}

impl From<[bool; 2]> for DebugSetting {
    fn from(bits: [bool; 2]) -> Self {
        let [fixed, enabled] = bits;
        use DebugSetting::*;
        //  UM, 517.1.4, Table 1064
        //  It seems that Enabled and Disabled are mixed up / incorrect in the table.
        //
        //  Indeed, AN13037 confirms this.
        match (fixed, enabled) {
            (true, true) => Enabled,
            (false, false) => Authenticate,
            (false, true) => Illegal,
            (true, false) => Disabled,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
// The `{non,}secure_{non,}invasive` settings pertain to CPU0,
// whereas CPU1 has two separate settings.
pub struct DebugSettings {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// non-invasive debugging of the TrustZone non-secure domain of CPU0
    pub nonsecure_noninvasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// invasive debugging of the TrustZone non-secure domain of CPU0
    pub nonsecure_invasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// non-invasive debugging of the TrustZone secure domain of CPU0
    pub secure_noninvasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// invasive debugging of the TrustZone secure domain of CPU0
    pub secure_invasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// non-invasive debugging of CPU1
    pub cpu1_noninvasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    /// invasive debugging of CPU1
    pub cpu1_invasive: DebugSetting,

    /// JTAG test access port
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub jtag_tap: DebugSetting,

    /// Flash mass erase command
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub flash_mass_erase_command: DebugSetting,

    /// ISP boot command
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub isp_boot_command: DebugSetting,
    /// FA (fault analysis) command
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub fault_analysis_command: DebugSetting,

    /// enforce UUID match during debug authentication
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub check_uuid: bool,
}

impl DebugSettings {
    pub fn are_all_legal(&self) -> bool {
        [
            self.nonsecure_noninvasive,
            self.nonsecure_invasive,
            self.secure_noninvasive,
            self.secure_invasive,
            self.cpu1_noninvasive,
            self.cpu1_invasive,
            self.jtag_tap,
            self.flash_mass_erase_command,
            self.isp_boot_command,
            self.fault_analysis_command,
        ]
        .iter()
        .all(|&setting| setting != DebugSetting::Illegal)
    }

    pub fn are_all_non_default(&self) -> bool {
        [
            self.nonsecure_noninvasive,
            self.nonsecure_invasive,
            self.secure_noninvasive,
            self.secure_invasive,
            self.cpu1_noninvasive,
            self.cpu1_invasive,
            self.jtag_tap,
            self.flash_mass_erase_command,
            self.isp_boot_command,
            self.fault_analysis_command,
        ]
        .iter()
        .all(|&setting| setting != DebugSetting::Default)
    }

    pub fn are_all_default(&self) -> bool {
        *self == DebugAccess::Default.into()
    }
}

impl From<DebugAccess> for DebugSettings {
    fn from(value: DebugAccess) -> Self {
        use DebugSetting::*;

        fn filled_with(setting: DebugSetting, check_uuid: bool) -> DebugSettings {
            DebugSettings {
                nonsecure_noninvasive: setting,
                nonsecure_invasive: setting,
                secure_noninvasive: setting,
                secure_invasive: setting,
                cpu1_noninvasive: setting,
                cpu1_invasive: setting,
                jtag_tap: setting,
                flash_mass_erase_command: setting,
                isp_boot_command: setting,
                fault_analysis_command: setting,
                check_uuid,
            }
        }
        match value {
            DebugAccess::Default => filled_with(Default, false),
            DebugAccess::Disabled => filled_with(Disabled, true),
            DebugAccess::Enabled => filled_with(Enabled, false),
            DebugAccess::Authenticate => filled_with(Authenticate, false),

            DebugAccess::Custom(settings) => settings,
        }
    }
}

impl From<DebugSettings> for DebugAccess {
    fn from(settings: DebugSettings) -> Self {
        if settings.are_all_default() {
            return DebugAccess::Default;
        };
        if settings == DebugAccess::Authenticate.into() {
            return DebugAccess::Authenticate;
        }
        if settings == DebugAccess::Disabled.into() {
            return DebugAccess::Disabled;
        }
        if settings == DebugAccess::Enabled.into() {
            return DebugAccess::Enabled;
        }
        DebugAccess::Custom(settings)
    }
}

impl From<[u32; 2]> for DebugSettings {
    fn from(value: [u32; 2]) -> Self {
        // fix = debugger can't change = PIN
        // set = DFLT
        let [fix, set] = value;
        if (fix, set) == (0, 0) {
            Self::from(DebugAccess::Default)
        } else {
            let from_bit =
                |bit: usize| DebugSetting::from([((fix >> bit) & 1) != 0, ((set >> bit) & 1) != 0]);
            Self {
                nonsecure_noninvasive: from_bit(0),
                nonsecure_invasive: from_bit(1),
                secure_noninvasive: from_bit(2),
                secure_invasive: from_bit(3),
                jtag_tap: from_bit(4),
                cpu1_invasive: from_bit(5),
                isp_boot_command: from_bit(6),
                fault_analysis_command: from_bit(7),
                flash_mass_erase_command: from_bit(8),
                cpu1_noninvasive: from_bit(9),
                check_uuid: ((fix >> 15) & 1) != 0,
            }
        }
    }
}

impl From<DebugSettings> for [u32; 2] {
    fn from(settings: DebugSettings) -> [u32; 2] {
        if settings.are_all_default() {
            return [0, 0];
        };

        assert!(settings.are_all_legal());
        assert!(settings.are_all_non_default());

        let mut fixed: u32 = 0;
        let mut enabled: u32 = 0;

        let mut set_bits = |setting: DebugSetting, bit: usize| {
            fixed |= setting.fixed_bit() << bit;
            enabled |= setting.enabled_bit() << bit;
        };

        set_bits(settings.nonsecure_noninvasive, 0);
        set_bits(settings.nonsecure_invasive, 1);
        set_bits(settings.secure_noninvasive, 2);
        set_bits(settings.secure_invasive, 3);
        set_bits(settings.jtag_tap, 4);
        set_bits(settings.cpu1_invasive, 5);
        set_bits(settings.isp_boot_command, 6);
        set_bits(settings.fault_analysis_command, 7);
        set_bits(settings.flash_mass_erase_command, 8);
        set_bits(settings.cpu1_noninvasive, 9);

        fixed |= (settings.check_uuid as u32) << 15;

        // "Inverse value of [15:0]"
        fixed |= ((!fixed) & 0xffff) << 16;
        enabled |= ((!enabled) & 0xffff) << 16;

        [fixed, enabled]
    }
}
