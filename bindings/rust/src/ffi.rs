// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! The declarations of include/noqtis.h this crate uses, written by hand.
//! The C enums (nqhalg, nqsalg, nqkalg) are passed as `c_int`.

use std::os::raw::{c_char, c_int};

pub const NQOK: c_int = 0;
pub const NQEBUF: c_int = -2;
pub const NQEVRFY: c_int = -3;
pub const NQEDEC: c_int = -4;

#[repr(C)]
#[derive(Default)]
pub struct Ssz {
    pub pk: usize,
    pub sk: usize,
    pub sig: usize,
}

#[repr(C)]
#[derive(Default)]
pub struct Ksz {
    pub pk: usize,
    pub sk: usize,
    pub ct: usize,
    pub ss: usize,
}

#[repr(C)]
pub struct Cin {
    pub id: [u8; 32],
    pub name: *const c_char,
}

#[repr(C)]
pub struct Copt {
    pub trust: *const u8,
    pub trustlen: usize,
    pub anc: *const *const u8,
    pub anclen: *const usize,
    pub nanc: usize,
    pub only: *const *const c_char,
    pub nonly: usize,
    pub lin: *const *const c_char,
    pub nlin: usize,
    pub stmt: *const *const c_char,
    pub stmtlen: *const usize,
    pub nstmt: usize,
}

/// nqcardf: a card that verified
#[repr(C)]
pub struct Cardf {
    pub alg: c_int,
    pub pk: [u8; 2624],
    pub pklen: usize,
    pub fp: [u8; 32],
    pub created: i64,
    pub utc: [c_char; 21],
    pub name: [c_char; 256],
    pub orcid: [c_char; 20],
    pub email: [c_char; 255],
    pub url: [c_char; 1025],
    pub affil: [c_char; 256],
}

#[repr(C)]
pub struct Rep {
    _p: [u8; 0],
}

extern "C" {
    pub fn nqerr(err: c_int) -> *const c_char;
    pub fn nqver() -> *const c_char;
    pub fn nqrand(buf: *mut u8, len: usize) -> c_int;

    pub fn nqhlen(alg: c_int) -> usize;
    pub fn nqhash(alg: c_int, inp: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> c_int;
    pub fn nqhmac(
        alg: c_int,
        key: *const u8,
        keylen: usize,
        inp: *const u8,
        inlen: usize,
        out: *mut u8,
        outlen: usize,
    ) -> c_int;

    pub fn nqssize(alg: c_int, sz: *mut Ssz) -> c_int;
    pub fn nqsname(alg: c_int) -> *const c_char;
    pub fn nqskg(alg: c_int, pk: *mut u8, pklen: usize, sk: *mut u8, sklen: usize) -> c_int;
    pub fn nqskgd(
        alg: c_int,
        seed: *const u8,
        seedlen: usize,
        pk: *mut u8,
        pklen: usize,
        sk: *mut u8,
        sklen: usize,
    ) -> c_int;
    pub fn nqsign(
        alg: c_int,
        sk: *const u8,
        sklen: usize,
        msg: *const u8,
        msglen: usize,
        ctx: *const u8,
        ctxlen: usize,
        ph: c_int,
        sig: *mut u8,
        siglen: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqsignd(
        alg: c_int,
        sk: *const u8,
        sklen: usize,
        msg: *const u8,
        msglen: usize,
        ctx: *const u8,
        ctxlen: usize,
        ph: c_int,
        rnd: *const u8,
        rndlen: usize,
        sig: *mut u8,
        siglen: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqvrfy(
        alg: c_int,
        pk: *const u8,
        pklen: usize,
        msg: *const u8,
        msglen: usize,
        ctx: *const u8,
        ctxlen: usize,
        ph: c_int,
        sig: *const u8,
        siglen: usize,
    ) -> c_int;

    pub fn nqksize(alg: c_int, sz: *mut Ksz) -> c_int;
    pub fn nqkname(alg: c_int) -> *const c_char;
    pub fn nqkkg(alg: c_int, pk: *mut u8, pklen: usize, sk: *mut u8, sklen: usize) -> c_int;
    pub fn nqkkgd(
        alg: c_int,
        seed: *const u8,
        seedlen: usize,
        pk: *mut u8,
        pklen: usize,
        sk: *mut u8,
        sklen: usize,
    ) -> c_int;
    pub fn nqenc(
        alg: c_int,
        pk: *const u8,
        pklen: usize,
        ct: *mut u8,
        ctlen: usize,
        ss: *mut u8,
        sslen: usize,
    ) -> c_int;
    pub fn nqencd(
        alg: c_int,
        pk: *const u8,
        pklen: usize,
        seed: *const u8,
        seedlen: usize,
        ct: *mut u8,
        ctlen: usize,
        ss: *mut u8,
        sslen: usize,
    ) -> c_int;
    pub fn nqdec(
        alg: c_int,
        sk: *const u8,
        sklen: usize,
        ct: *const u8,
        ctlen: usize,
        ss: *mut u8,
        sslen: usize,
    ) -> c_int;

    pub fn nqseal(
        dir: *const c_char,
        alg: c_int,
        sk: *const u8,
        sklen: usize,
        pk: *const u8,
        pklen: usize,
        meta: *const c_char,
        tsa: *const c_char,
    ) -> c_int;
    pub fn nqseal2(
        dir: *const c_char,
        alg: c_int,
        sk: *const u8,
        sklen: usize,
        pk: *const u8,
        pklen: usize,
        meta: *const c_char,
        inp: *const Cin,
        nin: usize,
    ) -> c_int;
    pub fn nqcapid(dir: *const c_char, id: *mut u8) -> c_int;
    pub fn nqchkx(dir: *const c_char, o: *const Copt, rep: *mut *mut Rep) -> c_int;
    pub fn nqprove(
        dir: *const c_char,
        paths: *const *const c_char,
        np: usize,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqchkp(
        proof: *const c_char,
        n: usize,
        o: *const Copt,
        dir: *const c_char,
        rep: *mut *mut Rep,
    ) -> c_int;
    pub fn nqinsp(dir: *const c_char, rep: *mut *mut Rep) -> c_int;
    pub fn nqfiles(dir: *const c_char, rep: *mut *mut Rep) -> c_int;
    pub fn nqrepn(r: *const Rep) -> usize;
    pub fn nqrepi(
        r: *const Rep,
        i: usize,
        check: *mut *const c_char,
        ok: *mut c_int,
        detail: *mut *const c_char,
    ) -> c_int;
    pub fn nqrepfree(r: *mut Rep);
    pub fn nqcard(
        alg: c_int,
        sk: *const u8,
        sklen: usize,
        pk: *const u8,
        pklen: usize,
        name: *const c_char,
        orcid: *const c_char,
        email: *const c_char,
        url: *const c_char,
        affil: *const c_char,
        created: i64,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqcardvrfy(
        card: *const c_char,
        n: usize,
        pk: *const u8,
        pklen: usize,
        f: *mut Cardf,
    ) -> c_int;
}
