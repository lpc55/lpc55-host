use std::fs::{self,File};
use std::io::Write;
use std::process::Command;

use tempfile::tempdir;
extern crate hex;

use assert_cmd::prelude::*;
use predicates::prelude::*;

#[test]
fn factory_generates_correctly() {
    let dir = tempdir().unwrap();

    let cfgfile_path = dir.path().join("cfg.toml");
    let mut cfgfile = File::create(cfgfile_path.clone()).unwrap();

    let binfile_path = dir.path().join("factory.bin");

    writeln!(cfgfile, r#"
[factory-settings]
usb-id = {{ vid = 0x1209, pid = 0xb000 }}
rot-fingerprint = "C7EE3124 DC87EAAE 5A6F7FCC B6C2E458 706835C9 9D5D7082 4EFFAC0F 12A5A875"
debug-access = "Disabled"

[factory-settings.boot-configuration]
failure-port  = 1
failure-pin = 21
speed = "48MHz"
mode = "Usb"

[factory-settings.secure-boot-configuration]
secure-boot-enabled = true
puf-enrollment-disabled = false
puf-keycode-generation-disabled = false
trustzone-mode = "FromImageHeader"
use-rsa4096-keys = false
dice-computation-disabled = true
"#).unwrap();

    let mut cmd = Command::cargo_bin("lpc55").unwrap();
    cmd
        .arg("configure")
        .arg("factory-settings")
        .arg("-o")
        .arg(binfile_path.clone())
        .arg(cfgfile_path);

    cmd.assert()
        .success();

    let data = fs::read(binfile_path).expect("Unable to read output factory file");

    assert_eq!(data.len(), 512);

    // boot config
    assert_eq!(data[0..4], [0x10, 0x01, 0x00, 0xa9]);
    // usb vid pid
    assert_eq!(data[8..12], [0x09, 0x12, 0x00, 0xb0]);

    // nothing
    assert_eq!(data[0x0c.. 0x10], [0x00u8; 4]);

    // debug policies
    assert_eq!(data[0x10.. 0x18], [0xff, 0x83, 0x00, 0x7c, 0x00, 0x00, 0xff, 0xff]);

    // nothing
    assert_eq!(data[0x18.. 0x1c], [0x00u8; 0x1c - 0x18]);

    // secure boot cfg
    assert_eq!(data[0x1c..0x20], [0xc0, 0x00, 0x00, 0xc0]);

    // nothing
    assert_eq!(data[0x20 .. 0x50], [0x00u8; 0x50 - 0x20]);

    // rotkh
    assert_eq!(
        data[0x50 .. 0x70],
        hex::decode("C7EE3124DC87EAAE5A6F7FCCB6C2E458706835C99D5D70824EFFAC0F12A5A875").unwrap()
    );

    // nothing
    assert_eq!(data[0x70 .. 0x200], [0x00u8; 0x200 - 0x70]);
}

#[test]
fn customer_generates_correctly() {
    let dir = tempdir().unwrap();

    let cfgfile_path = dir.path().join("cfg.toml");
    let mut cfgfile = File::create(cfgfile_path.clone()).unwrap();

    let binfile_path = dir.path().join("customer.bin");

    writeln!(cfgfile, r#"
[customer-settings]
customer-version = 0x030201
nonsecure-firmware-version = 0x060504
secure-firmware-version = 0x090807
rot-keys-status = ["Enabled", "Enabled", "Enabled", "Enabled"]
"#).unwrap();

    let mut cmd = Command::cargo_bin("lpc55").unwrap();
    cmd
        .arg("configure")
        .arg("customer-settings")
        .arg("-o")
        .arg(binfile_path.clone())
        .arg(cfgfile_path);

    cmd.assert()
        .success();

    let data = fs::read(binfile_path).expect("Unable to read output customer file");

    assert_eq!(data.len(), 512);
    // nothing
    assert_eq!(data[0..4], [0u8; 4]);
    // versions
    assert_eq!(data[4 .. 16], [1, 2, 3, 0, 7, 8, 9, 0, 4, 5, 6, 0]);
    // nothing
    assert_eq!(data[0x10..0x18], [0u8; 8]);
    // revocations
    assert_eq!(data[0x18 .. 0x1c], [0x55, 0, 0, 0]);
    // nothing
    assert_eq!(data[0x1c..0x20], [0u8; 4]);
    // debug policies
    assert_eq!(data[0x20.. 0x28], [0u8; 8]);
    // nothing
    assert_eq!(data[0x28..0x200], [0u8; 0x200 - 0x28]);
}

#[test]
fn custom_debug_policy() {
    let dir = tempdir().unwrap();

    let cfgfile_path = dir.path().join("cfg.toml");
    let mut cfgfile = File::create(cfgfile_path.clone()).unwrap();

    let binfile_path = dir.path().join("customer.bin");

    // Needs to all be inline due to serde bug
    // https://github.com/alexcrichton/toml-rs/issues/225
    writeln!(cfgfile, r#"
[factory-settings]
debug-access = {{ Custom = {{ nonsecure-noninvasive = "Disabled", secure-invasive = "Authenticate", jtag-tap = "Enabled" }} }}
"#).unwrap();

    let mut cmd = Command::cargo_bin("lpc55").unwrap();
    cmd
        .arg("configure")
        .arg("factory-settings")
        .arg("-o")
        .arg(binfile_path.clone())
        .arg(cfgfile_path);

    cmd.assert()
        .success();

    let data = fs::read(binfile_path).expect("Unable to read output customer file");

   // debug policies, default Enabled
    assert_eq!(data[0x10.. 0x18], [0xf7, 0x03, 0x08, 0xfc, 0xf6, 0x03, 0x09, 0xfc]);
}

#[test]
fn sha256_seal () {
    let dir = tempdir().unwrap();

    let cfgfile_path = dir.path().join("cfg.toml");
    let mut cfgfile = File::create(cfgfile_path.clone()).unwrap();

    let binfile_path = dir.path().join("factory.bin");

    // Needs to all be inline due to serde bug
    // https://github.com/alexcrichton/toml-rs/issues/225
    writeln!(cfgfile, r#"
[factory-settings]
usb-id = {{ vid = 0x1209, pid = 0xb000 }}
rot-fingerprint = "C7EE3124 DC87EAAE 5A6F7FCC B6C2E458 706835C9 9D5D7082 4EFFAC0F 12A5A875"
debug-access = "Disabled"
seal = true
"#).unwrap();

    let mut cmd = Command::cargo_bin("lpc55").unwrap();
    cmd
        .arg("configure")
        .arg("factory-settings")
        .arg("-o")
        .arg(binfile_path.clone())
        .arg(cfgfile_path);

    cmd.assert()
        .success();

    let data = fs::read(binfile_path).expect("Unable to read output factory file");

    // sha256
    assert_eq!(
        data[480 .. 512],
        hex::decode("11c38ce9fa006c6fda5f894c5ab679bd0a6dc01dfac2dc3e25a7670bd1e1752d").unwrap()
    );
}

#[test]
fn rotkh() {

    let mut cmd = Command::cargo_bin("lpc55").unwrap();
    cmd
        .arg("fingerprint-certificates")
        .arg("./example-cfgs/example-cfg.toml");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("D826E2FD 44F5C254 BC58C62E BF96A938 95C19DC2 25810C95 C8B9E6FD 9F7CC9CB"));

}

