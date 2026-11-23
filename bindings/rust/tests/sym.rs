// SPDX-License-Identifier: LGPL-3.0-or-later
//! KangarooTwelve, ChaCha20, AES-SIV and AES-GCM-SIV: an answer of each
//! RFC, the round trips and the refusals.
use noqtis::Code;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn ptn(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn code<T: std::fmt::Debug>(r: noqtis::Result<T>) -> Code {
    r.unwrap_err().kind()
}

#[test]
fn kangarootwelve_rfc9861() {
    assert_eq!(
        noqtis::kt128(b"", b"", 32).unwrap(),
        unhex("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")
    );
    assert_eq!(
        noqtis::kt128(&ptn(17), b"", 32).unwrap(),
        unhex("6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888")
    );
    assert_eq!(
        noqtis::kt128(&[0xff], &ptn(41), 32).unwrap(),
        unhex("d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4")
    );
    assert_eq!(
        noqtis::kt256(b"", b"", 32).unwrap(),
        unhex("b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404")
    );
    let big = ptn(20000);
    assert_eq!(
        noqtis::kt128(&big, b"", 100).unwrap()[..32],
        noqtis::kt128(&big, b"", 32).unwrap()[..]
    );
    assert_ne!(
        noqtis::kt128(&big, b"a", 32).unwrap(),
        noqtis::kt128(&big, b"", 32).unwrap()
    );
    assert_eq!(noqtis::kt256(&big, b"", 64).unwrap().len(), 64);
    assert_eq!(code(noqtis::kt128(b"x", b"", 0)), Code::Arg);
}

#[test]
fn chacha20_rfc8439() {
    assert_eq!(
        noqtis::chacha20(&[0; 32], &[0; 12], 0, &[0; 64]).unwrap(),
        unhex(concat!(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
            "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        ))
    );
    let (k, n, m) = (ptn(32), ptn(12), ptn(300));
    let c = noqtis::chacha20(&k, &n, 7, &m).unwrap();
    assert_ne!(c, m);
    assert_eq!(noqtis::chacha20(&k, &n, 7, &c).unwrap(), m);
    assert_eq!(noqtis::chacha20(&k, &n, 8, &m[64..]).unwrap(), c[64..]);
    assert_eq!(noqtis::chacha20(&k, &n, 0, b"").unwrap(), b"");
    assert_eq!(code(noqtis::chacha20(&k, &n, u32::MAX, &m)), Code::Limit);
    assert_eq!(code(noqtis::chacha20(&k[..16], &n, 0, &m)), Code::Arg);
    assert_eq!(code(noqtis::chacha20(&k, &n[..8], 0, &m)), Code::Arg);
}

#[test]
fn aes_siv_rfc5297() {
    let key = unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let ad = unhex("101112131415161718191a1b1c1d1e1f2021222324252627");
    let pt = unhex("112233445566778899aabbccddee");
    let out = unhex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");
    assert_eq!(noqtis::sivenc(&key, &[&ad], &pt).unwrap(), out);
    assert_eq!(noqtis::sivdec(&key, &[&ad], &out).unwrap(), pt);
    assert_ne!(noqtis::sivenc(&key, &[], &pt).unwrap(), out);
    assert_ne!(noqtis::sivenc(&key, &[&ad, b""], &pt).unwrap(), out);
    for k in [ptn(48), ptn(64)] {
        let c = noqtis::sivenc(&k, &[&ad, b"n"], &pt).unwrap();
        assert_eq!(noqtis::sivdec(&k, &[&ad, b"n"], &c).unwrap(), pt);
    }
    let e = noqtis::sivenc(&key, &[], b"").unwrap();
    assert_eq!(noqtis::sivdec(&key, &[], &e).unwrap(), b"");
    let mut bad = out.clone();
    bad[20] ^= 1;
    assert_eq!(code(noqtis::sivdec(&key, &[&ad], &bad)), Code::Verify);
    assert_eq!(code(noqtis::sivdec(&key, &[], &out)), Code::Verify);
    assert_eq!(code(noqtis::sivdec(&ptn(32), &[&ad], &out)), Code::Verify);
    assert_eq!(code(noqtis::sivenc(&ptn(40), &[], &pt)), Code::Arg);
    assert_eq!(code(noqtis::sivdec(&key, &[], b"short")), Code::Arg);
    let many: Vec<&[u8]> = vec![b"a"; 127];
    assert_eq!(code(noqtis::sivenc(&key, &many, &pt)), Code::Arg);
}

#[test]
fn aes_gcm_siv_rfc8452() {
    let key = unhex("01000000000000000000000000000000");
    let nonce = unhex("030000000000000000000000");
    let pt = unhex("0100000000000000");
    let out = unhex("b5d839330ac7b786578782fff6013b815b287c22493a364c");
    assert_eq!(noqtis::gsivenc(&key, &nonce, b"", &pt).unwrap(), out);
    assert_eq!(noqtis::gsivdec(&key, &nonce, b"", &out).unwrap(), pt);
    let k2 = ptn(32);
    let c = noqtis::gsivenc(&k2, &nonce, b"header", &pt).unwrap();
    assert_eq!(noqtis::gsivdec(&k2, &nonce, b"header", &c).unwrap(), pt);
    let mut bad = c.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x80;
    assert_eq!(
        code(noqtis::gsivdec(&k2, &nonce, b"header", &bad)),
        Code::Verify
    );
    assert_eq!(
        code(noqtis::gsivdec(&k2, &nonce, b"other", &c)),
        Code::Verify
    );
    assert_eq!(
        code(noqtis::gsivdec(&k2, &ptn(12), b"header", &c)),
        Code::Verify
    );
    assert_eq!(code(noqtis::gsivenc(&ptn(24), &nonce, b"", &pt)), Code::Arg);
    assert_eq!(code(noqtis::gsivenc(&key, &ptn(8), b"", &pt)), Code::Arg);
    assert_eq!(code(noqtis::gsivdec(&key, &nonce, b"", b"xyz")), Code::Arg);
}
