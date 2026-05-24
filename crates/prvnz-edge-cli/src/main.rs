// SPDX-License-Identifier: Apache-2.0

//! `prvnz-edge` CLI — Pi-class PRVNZ DPP participation.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "prvnz-edge",
    version,
    about = "Pi-class PRVNZ DPP participation runtime"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Issue a Digital Product Passport.
    Issue {
        /// Product ID (GTIN or other DPP-recognised identifier).
        #[arg(long)]
        product_id: String,
        /// Batch identifier.
        #[arg(long)]
        batch: String,
    },
    /// Verify a Digital Product Passport.
    Verify {
        /// Passport JWS / VC bundle, or `@path/to/file`.
        #[arg(long)]
        passport: String,
    },
    /// Flush any offline-buffered passports.
    Replay,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Issue {
            product_id: _,
            batch: _,
        } => {
            eprintln!("prvnz-edge issue: not yet implemented (v0.1.0 scaffold)");
        }
        Cmd::Verify { passport: _ } => {
            eprintln!("prvnz-edge verify: not yet implemented (v0.1.0 scaffold)");
        }
        Cmd::Replay => {
            eprintln!("prvnz-edge replay: not yet implemented (v0.1.0 scaffold)");
        }
    }
}
