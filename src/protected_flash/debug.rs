use serde::{Deserialize, Serialize};

use crate::util::is_default;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,Serialize)]
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
/// - The disabled bit ("DFLT") determines which setting is potentially in effect
/// - The fixed bit ("PIN") determines whether a debugger may activate the potentially
///   effective settings (by presenting a Debug Authentication certificate)
/// - The non-fixed disabled setting is illegal.
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
    /// The interpretation is that the setting in the "disabled"
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
    fn disabled_bit(&self) -> u32 {
        use DebugSetting::*;
        match *self {
            Enabled | Default | Authenticate => 0,
            Disabled | Illegal => 1,
        }
    }
}

impl From<[bool; 2]> for DebugSetting {
    fn from(bits: [bool; 2]) -> Self {
        let [fixed, disabled] = bits;
        use DebugSetting::*;
        //  UM, 517.1.4, Table 1064
        match (fixed, disabled) {
            (true, false) => Enabled,
            (false, false) => Authenticate,
            (false, true) => Illegal,
            (true, true) => Disabled,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DebugSettings {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub nonsecure_noninvasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub nonsecure_invasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub secure_noninvasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub secure_invasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub cm33_invasive: DebugSetting,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub cm33_noninvasive: DebugSetting,

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
            self.cm33_invasive,
            self.cm33_noninvasive,
            self.jtag_tap,
            self.flash_mass_erase_command,
            self.isp_boot_command,
            self.fault_analysis_command,
        ].iter()
            .all(|&setting| setting != DebugSetting::Illegal)
    }

    pub fn are_all_non_default(&self) -> bool {
        [
            self.nonsecure_noninvasive,
            self.nonsecure_invasive,
            self.secure_noninvasive,
            self.secure_invasive,
            self.cm33_invasive,
            self.cm33_noninvasive,
            self.jtag_tap,
            self.flash_mass_erase_command,
            self.isp_boot_command,
            self.fault_analysis_command,
        ].iter()
            .all(|&setting| setting != DebugSetting::Default)
    }

    pub fn are_all_default(&self) -> bool {
        *self == DebugAccess::Default.into()
    }
}

impl From<DebugAccess> for DebugSettings {
    fn from(value: DebugAccess) -> Self {
        use DebugSetting::*;
        match value {
            // Default state
            DebugAccess::Default => DebugSettings {
                nonsecure_noninvasive: Default,
                nonsecure_invasive: Default,
                secure_noninvasive: Default,
                secure_invasive: Default,
                cm33_invasive: Default,
                cm33_noninvasive: Default,
                jtag_tap: Default,
                flash_mass_erase_command: Default,
                isp_boot_command: Default,
                fault_analysis_command: Default,
                check_uuid: false,
            },

            // Fixed, Disabled
            DebugAccess::Disabled => DebugSettings {
                nonsecure_noninvasive: Disabled,
                nonsecure_invasive: Disabled,
                secure_noninvasive: Disabled,
                secure_invasive: Disabled,
                cm33_invasive: Disabled,
                cm33_noninvasive: Disabled,
                jtag_tap: Disabled,
                flash_mass_erase_command: Disabled,
                isp_boot_command: Disabled,
                fault_analysis_command: Disabled,
                check_uuid: true,
            },

            // Fixed, Enabled
            DebugAccess::Enabled => DebugSettings {
                nonsecure_noninvasive: Enabled,
                nonsecure_invasive: Enabled,
                secure_noninvasive: Enabled,
                secure_invasive: Enabled,
                cm33_invasive: Enabled,
                cm33_noninvasive: Enabled,
                jtag_tap: Enabled,
                flash_mass_erase_command: Enabled,
                isp_boot_command: Enabled,
                fault_analysis_command: Enabled,
                check_uuid: false,
            },

            // Not fixed, debugger must authenticate
            DebugAccess::Authenticate => DebugSettings {
                nonsecure_noninvasive: Authenticate,
                nonsecure_invasive: Authenticate,
                secure_noninvasive: Authenticate,
                secure_invasive: Authenticate,
                cm33_invasive: Authenticate,
                cm33_noninvasive: Authenticate,
                jtag_tap: Authenticate,
                flash_mass_erase_command: Authenticate,
                isp_boot_command: Authenticate,
                fault_analysis_command: Authenticate,
                check_uuid: false,
            },

            DebugAccess::Custom ( settings ) =>
                settings,
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
            Self {
                nonsecure_noninvasive: DebugSetting::from([
                    ((fix >> 0) & 1) != 0,
                    ((set >> 0) & 1) != 0,
                ]),
                nonsecure_invasive: DebugSetting::from([
                    ((fix >> 1) & 1) != 0,
                    ((set >> 1) & 1) != 0,
                ]),
                secure_noninvasive: DebugSetting::from([
                    ((fix >> 2) & 1) != 0,
                    ((set >> 2) & 1) != 0,
                ]),
                secure_invasive: DebugSetting::from([
                    ((fix >> 3) & 1) != 0,
                    ((set >> 3) & 1) != 0,
                ]),
                jtag_tap: DebugSetting::from([
                    ((fix >> 4) & 1) != 0,
                    ((set >> 4) & 1) != 0,
                ]),
                cm33_invasive: DebugSetting::from([
                    ((fix >> 5) & 1) != 0,
                    ((set >> 5) & 1) != 0,
                ]),
                isp_boot_command: DebugSetting::from([
                    ((fix >> 6) & 1) != 0,
                    ((set >> 6) & 1) != 0,
                ]),
                fault_analysis_command: DebugSetting::from([
                    ((fix >> 7) & 1) != 0,
                    ((set >> 7) & 1) != 0,
                ]),
                flash_mass_erase_command: DebugSetting::from([
                    ((fix >> 8) & 1) != 0,
                    ((set >> 8) & 1) != 0,
                ]),
                cm33_noninvasive: DebugSetting::from([
                    ((fix >> 9) & 1) != 0,
                    ((set >> 9) & 1) != 0,
                ]),
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
        let mut disabled: u32 = 0;

        fixed |= settings.nonsecure_noninvasive.fixed_bit() << 0;
        disabled |= settings.nonsecure_noninvasive.disabled_bit() << 0;

        fixed |= settings.nonsecure_invasive.fixed_bit() << 1;
        disabled |= settings.nonsecure_invasive.disabled_bit() << 1;

        fixed |= settings.secure_noninvasive.fixed_bit() << 2;
        disabled |= settings.secure_noninvasive.disabled_bit() << 2;

        fixed |= settings.secure_invasive.fixed_bit() << 3;
        disabled |= settings.secure_invasive.disabled_bit() << 3;

        fixed |= settings.jtag_tap.fixed_bit() << 4;
        disabled |= settings.jtag_tap.disabled_bit() << 4;

        fixed |= settings.cm33_invasive.fixed_bit() << 5;
        disabled |= settings.cm33_invasive.disabled_bit() << 5;

        fixed |= settings.isp_boot_command.fixed_bit() << 6;
        disabled |= settings.isp_boot_command.disabled_bit() << 6;

        fixed |= settings.fault_analysis_command.fixed_bit() << 7;
        disabled |= settings.fault_analysis_command.disabled_bit() << 7;

        fixed |= settings.flash_mass_erase_command.fixed_bit() << 8;
        disabled |= settings.flash_mass_erase_command.disabled_bit() << 8;

        fixed |= settings.cm33_noninvasive.fixed_bit() << 9;
        disabled |= settings.cm33_noninvasive.disabled_bit() << 9;

        fixed |= (settings.check_uuid as u32) << 15;

        // "Inverse value of [15:0]"
        fixed |= ((!fixed) & 0xffff) << 16;
        disabled |= ((!disabled) & 0xffff) << 16;

        [fixed, disabled]
    }
}

