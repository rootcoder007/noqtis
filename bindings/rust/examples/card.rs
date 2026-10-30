// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
use noqtis::{card, sign};

fn main() -> noqtis::Result<()> {
    let (pk, sk) = sign::keygen("ML-DSA-65", None)?;
    let f = card::Fields {
        orcid: Some("https://orcid.org/0000-0002-1825-0097"),
        url: Some("https://example.org/ada"),
        ..card::Fields::new("Ada Lovelace")
    };
    let c = card::make("ML-DSA-65", &sk, &pk, &f, None)?;

    // None unless it verifies and is pk's
    if let Some(v) = card::verify(&c, Some(&pk))? {
        println!("name: {}", v.name);
        println!("orcid: {}", v.orcid.unwrap_or_default());
    }

    // a changed card does not verify; a wrong check digit is refused
    let t = String::from_utf8_lossy(&c).replace("Ada", "Eve");
    println!("changed: {:?}", card::verify(t.as_bytes(), None)?);
    let bad = card::Fields {
        orcid: Some("0000-0002-1825-0098"),
        ..card::Fields::new("Ada Lovelace")
    };
    let e = card::make("ML-DSA-65", &sk, &pk, &bad, None).unwrap_err();
    println!("refused: {:?}", e.kind());
    Ok(())
}
