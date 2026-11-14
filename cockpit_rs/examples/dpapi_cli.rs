//! TEST-ONLY HELPER: Cross-language DPAPI interoperability test utility.
//! Strictly intended for integration testing between Rust and Python.
//! Do not use in production or log pipelines.
//!
//! Payload is read strictly from stdin to prevent leaking secrets in process listings.
//! Usage:
//!   printf '%s' "plaintext" | cargo run --example dpapi_cli -- protect
//!   printf '%s' "dpapi:..." | cargo run --example dpapi_cli -- unprotect

use cockpit_rs::secrets::secret_store::{dpapi_protect, dpapi_unprotect_strict, SecretStatus};
use std::env;
use std::io::{self, Read, Write};
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: dpapi_cli <protect|unprotect> (payload read strictly from stdin)");
        process::exit(1);
    }

    let command = &args[1];

    let mut payload = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut payload) {
        eprintln!("Failed to read stdin: {}", e);
        process::exit(1);
    }

    // Strip only one trailing \r\n or \n if present (preserves internal and leading spaces)
    if payload.ends_with('\n') {
        payload.pop();
        if payload.ends_with('\r') {
            payload.pop();
        }
    }

    match command.as_str() {
        "protect" => match dpapi_protect(&payload, Some("OpenViking DPAPI")) {
            Ok(cipher) => {
                print!("{}", cipher);
                let _ = io::stdout().flush();
            }
            Err(err) => {
                eprintln!("Protect error: {}", err);
                process::exit(1);
            }
        },
        "unprotect" => {
            let res = dpapi_unprotect_strict(&payload);
            if res.status == SecretStatus::SecretReady {
                print!("{}", res.value);
                let _ = io::stdout().flush();
            } else {
                eprintln!(
                    "Unprotect error: status={:?}, msg={:?}",
                    res.status, res.error_message
                );
                process::exit(1);
            }
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            process::exit(1);
        }
    }
}
