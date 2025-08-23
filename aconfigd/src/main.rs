/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! `aconfigd-mainline` is a daemon binary that responsible for:
//! (1) initialize mainline storage files
//! (2) initialize and maintain a persistent socket based service

use clap::Parser;
use kernlog::KernelLog;
use log::{error, info, warn};
use std::panic;
use std::path::Path;

mod aconfigd_commands;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// start aconfigd socket.
    StartSocket,

    /// early initialize platform storage files during early-init phase. Might fail
    /// during post data-wipe boot.
    EarlyPlatformInit,

    /// initialize platform storage files during post-fs phase, no op if early-init
    /// phase start is successful.
    PlatformInit,
}

// Main error code, DO NOT REMOVE, ONLY ADD
enum ErrCode {
    InitOnceFail = 1,
    KernelLoggerSetFail = 2,
    KernelLoggerCreateFail = 3,
    SocketStartFail = 4,
    EarlyPlatformInitFail = 5,
    PlatformInitFail = 6,
}

const EARLY_INIT_MARKER: &str = "/metadata/aconfig/early_init_done";

// A helper function to reduce boilerplate for error handling.
fn handle_error_and_exit<E: std::fmt::Debug>(error: E, message: &str, code: ErrCode) -> ! {
    error!("{}: {:?}", message, error);
    std::process::exit(code as i32);
}

// Sets up the appropriate logger based on the command.
fn setup_logger(command: &Command) {
    // SAFETY: nobody has taken ownership of the inherited FDs yet.
    // This needs to be called before logger initialization as logger setup will
    // create a file descriptor.
    unsafe {
        rustutils::inherited_fd::init_once().unwrap_or_else(|e| {
            handle_error_and_exit(
                e,
                "failed to run init_once for inherited fds",
                ErrCode::InitOnceFail,
            );
        });
    };

    match command {
        Command::EarlyPlatformInit => {
            let klog = KernelLog::with_level(log::LevelFilter::Trace).unwrap_or_else(|e| {
                handle_error_and_exit(
                    e,
                    "failed to create kernel logger",
                    ErrCode::KernelLoggerCreateFail,
                );
            });
            log::set_boxed_logger(Box::new(klog)).unwrap_or_else(|e| {
                handle_error_and_exit(
                    e,
                    "failed to set kernel logger",
                    ErrCode::KernelLoggerSetFail,
                );
            });
            log::set_max_level(log::LevelFilter::Trace);
        }
        Command::StartSocket | Command::PlatformInit => {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_tag("aconfigd_system")
                    .with_max_level(log::LevelFilter::Trace),
            );
        }
    }
}

// Handles the logic for the EarlyPlatformInit command.
fn handle_early_init() {
    if !aconfig_new_storage_flags::enable_earlier_aconfigd() {
        return;
    }

    info!("Starting early-init platform init");

    // Clean up marker from a previous failed boot, if it exists.
    let marker_path = Path::new(EARLY_INIT_MARKER);
    if marker_path.try_exists().unwrap_or_else(|e| {
        handle_error_and_exit(
            e,
            "Failed to check for early init marker",
            ErrCode::EarlyPlatformInitFail,
        )
    }) {
        warn!("Detected early init marker from previous boot; removing it.");
        std::fs::remove_file(marker_path).unwrap_or_else(|e| {
            handle_error_and_exit(
                e,
                "Failed to remove early init marker",
                ErrCode::EarlyPlatformInitFail,
            )
        });
    }

    // Run the init and create a marker file on success.
    aconfigd_commands::platform_init().unwrap_or_else(|e| {
        handle_error_and_exit(
            e,
            "Failed to initialize platform storage in early init",
            ErrCode::EarlyPlatformInitFail,
        );
    });

    std::fs::File::create(EARLY_INIT_MARKER).unwrap_or_else(|e| {
        handle_error_and_exit(
            e,
            "Failed to create early init success marker",
            ErrCode::EarlyPlatformInitFail,
        );
    });
}

// Handles the logic for the PlatformInit command.
// post-fs platform init is needed only if early-init platform init failed (during post
// data wipe boot)
fn handle_platform_init() {
    if aconfig_new_storage_flags::enable_earlier_aconfigd() {
        let marker_path = Path::new(EARLY_INIT_MARKER);

        // We only need to run this if the early init did not succeed (i.e., the marker is absent).
        let early_init_succeeded = marker_path.try_exists().unwrap_or_else(|e| {
            handle_error_and_exit(
                e,
                "Failed to check for early init marker",
                ErrCode::PlatformInitFail,
            );
        });

        if early_init_succeeded {
            info!("Skipping post-fs platform init due to early-init success.");
            std::fs::remove_file(marker_path).unwrap_or_else(|e| {
                handle_error_and_exit(
                    e,
                    "Failed to remove early init marker",
                    ErrCode::PlatformInitFail,
                );
            });
        } else {
            info!("Starting post-fs platform init due to early-init failure.");
            aconfigd_commands::platform_init().unwrap_or_else(|e| {
                handle_error_and_exit(
                    e,
                    "Failed to initialize platform storage in post-fs",
                    ErrCode::PlatformInitFail,
                );
            });
        }
    } else {
        aconfigd_commands::platform_init().unwrap_or_else(|e| {
            handle_error_and_exit(
                e,
                "Failed to initialize platform storage in post-fs",
                ErrCode::PlatformInitFail,
            );
        });
    }
}

fn main() {
    let cli = Cli::parse();
    setup_logger(&cli.command);

    if !aconfig_new_storage_flags::enable_aconfig_storage_daemon() {
        info!("aconfigd_system is disabled by feature flag, exiting.");
        std::process::exit(0);
    }

    info!("Starting aconfigd_system command: {:?}", &cli.command);

    match cli.command {
        Command::StartSocket => {
            if cfg!(enable_system_aconfigd_socket) {
                info!("aconfigd_system is build-enabled, starting socket.");
                aconfigd_commands::start_socket().unwrap_or_else(|e| {
                    handle_error_and_exit(
                        e,
                        "failed to start aconfigd socket",
                        ErrCode::SocketStartFail,
                    );
                });
            } else {
                info!("aconfigd_system is build-disabled, exiting.");
            }
        }
        Command::EarlyPlatformInit => {
            handle_early_init();
        }
        Command::PlatformInit => {
            handle_platform_init();
        }
    }
}
