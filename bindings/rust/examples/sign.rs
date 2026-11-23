// SPDX-License-Identifier: LGPL-3.0-or-later
use noqtis::sign::{self, Opts};

fn main() -> noqtis::Result<()> {
    let (pk, sk) = sign::keygen("ML-DSA-65", None)?;
    let o = Opts {
        ctx: b"app-v1",
        ..Opts::default()
    };
    let sig = sign::sign("ML-DSA-65", &sk, b"the results in table 2", &o)?;
    println!("signature: {} bytes", sig.len());
    println!(
        "verify: {}",
        sign::verify("ML-DSA-65", &pk, b"the results in table 2", &sig, &o)?
    );
    println!(
        "other message: {}",
        sign::verify("ML-DSA-65", &pk, b"other", &sig, &o)?
    );
    Ok(())
}
