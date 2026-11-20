// SPDX-License-Identifier: Apache-2.0

//! Read-only operator check. The provider credential arrives through private stdin.

use std::{
    env,
    io::{self, IsTerminal as _, Read as _},
    process::ExitCode,
};

use oxid_adapter_midnight::{MidnightPreprodCredential, preflight_blockfrost_preprod};
use zeroize::Zeroizing;

fn main() -> ExitCode {
    match run() {
        Ok(height) => {
            println!("PreProd node and indexer agree at height {height}");
            println!("PreProd GraphQL WebSocket acknowledged the authenticated session");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("PreProd preflight failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u64, Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let mut genesis = [0; 32];
    let expected_genesis = arguments.next().ok_or("expected reviewed genesis hex")?;
    if arguments.next().is_some() {
        return Err("expected only reviewed genesis hex as a command-line argument".into());
    }
    hex::decode_to_slice(
        expected_genesis
            .strip_prefix("0x")
            .unwrap_or(&expected_genesis),
        &mut genesis,
    )
    .map_err(|_| "expected a 32-byte reviewed genesis hash")?;

    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err("supply the PreProd credential through a private pipe".into());
    }
    let mut secret = Zeroizing::new(String::new());
    stdin
        .lock()
        .take(130)
        .read_to_string(&mut secret)
        .map_err(|_| "could not read the PreProd credential")?;
    if secret.ends_with('\n') {
        secret.pop();
    }
    let credential = MidnightPreprodCredential::new(std::mem::take(&mut *secret))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "could not start the native transport runtime")?;
    Ok(runtime.block_on(preflight_blockfrost_preprod(
        "wss://rpc.midnight-preprod.blockfrost.io",
        "https://midnight-preprod.blockfrost.io/api/v0",
        "wss://midnight-preprod.blockfrost.io/api/v0/ws",
        &genesis,
        &credential,
    ))?)
}
