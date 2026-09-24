use std::process::Command;

use assert_cmd::{cargo, prelude::*};
use clap::{ValueEnum, crate_version};
use clap_complete::Shell;

mod fixtures;

use crate::fixtures::Error;

#[test]
/// Show help and exit.
fn help_shows() -> Result<(), Error> {
    Command::new(cargo::cargo_bin!("miniserve-axum"))
        .arg("-h")
        .assert()
        .success();

    Ok(())
}

#[test]
/// Show version and exit.
fn version_shows() -> Result<(), Error> {
    Command::new(cargo::cargo_bin!("miniserve-axum"))
        .arg("-V")
        .assert()
        .success()
        .stdout(format!("miniserve {}\n", crate_version!()));

    Ok(())
}

#[test]
/// Print completions and exit.
fn print_completions() -> Result<(), Error> {
    for shell in Shell::value_variants() {
        Command::new(cargo::cargo_bin!("miniserve-axum"))
            .arg("--print-completions")
            .arg(shell.to_string())
            .assert()
            .success();
    }

    Ok(())
}

#[test]
/// Print completions rejects invalid shells.
fn print_completions_invalid_shell() -> Result<(), Error> {
    Command::new(cargo::cargo_bin!("miniserve-axum"))
        .arg("--print-completions")
        .arg("fakeshell")
        .assert()
        .failure();

    Ok(())
}
