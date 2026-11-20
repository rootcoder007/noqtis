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
    pub fn nqselftest() -> c_int;
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

/// nqdrec: a data record (opaque)
#[repr(C)]
pub struct Drec {
    _p: [u8; 0],
}

/// nqdrep: a data check's rows (opaque)
#[repr(C)]
pub struct Drep {
    _p: [u8; 0],
}

/// nqdcsvopt
#[repr(C)]
pub struct Csvopt {
    pub delim: c_char,
    pub noheader: c_int,
    pub ranges: c_int,
}

/// nqddopt
#[repr(C)]
pub struct Dopt {
    pub psiwarn: f64,
    pub psifail: f64,
    pub alpha: f64,
    pub minn: f64,
    pub benford: c_int,
}

// include/nqd.h, the data layer
extern "C" {
    pub fn nqdnew(r: *mut *mut Drec) -> c_int;
    pub fn nqdparse(
        json: *const c_char,
        n: usize,
        r: *mut *mut Drec,
        why: *mut c_char,
        cap: usize,
    ) -> c_int;
    pub fn nqdload(dir: *const c_char, r: *mut *mut Drec, why: *mut c_char, cap: usize) -> c_int;
    pub fn nqdjson(r: *const Drec, out: *mut c_char, cap: usize, outlen: *mut usize) -> c_int;
    pub fn nqdsave(r: *const Drec, dir: *const c_char) -> c_int;
    pub fn nqdrfree(r: *mut Drec);
    pub fn nqdlen(r: *const Drec, member: *const c_char) -> usize;
    pub fn nqdat(
        r: *const Drec,
        member: *const c_char,
        i: usize,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdkey(
        r: *const Drec,
        member: *const c_char,
        key: *const c_char,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdput(
        r: *mut Drec,
        member: *const c_char,
        json: *const c_char,
        n: usize,
        why: *mut c_char,
        cap: usize,
    ) -> c_int;
    pub fn nqddel(r: *mut Drec, member: *const c_char, key: *const c_char) -> c_int;
    pub fn nqdset(
        r: *mut Drec,
        member: *const c_char,
        key: *const c_char,
        field: *const c_char,
        json: *const c_char,
        n: usize,
        why: *mut c_char,
        cap: usize,
    ) -> c_int;
    pub fn nqdaddr(
        r: *const Drec,
        path: *const c_char,
        i: usize,
        kind: *mut c_int,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdvrfy(r: *const Drec, path: *const c_char, b: *const u8, n: usize) -> c_int;
    pub fn nqdfld(
        r: *const Drec,
        member: *const c_char,
        i: usize,
        field: *const c_char,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdrslv(
        rslv: *const c_char,
        n: usize,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
        why: *mut c_char,
        wcap: usize,
    ) -> c_int;
    pub fn nqdrsp(
        rslv: *const c_char,
        n: usize,
        reply: *const c_char,
        rn: usize,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
        tm: *mut c_char,
        why: *mut c_char,
        wcap: usize,
    ) -> c_int;
    pub fn nqdwb(url: *const c_char, out: *mut c_char, cap: usize, outlen: *mut usize) -> c_int;
    pub fn nqdsrc(
        r: *mut Drec,
        dir: *const c_char,
        path: *const c_char,
        why: *mut c_char,
        cap: usize,
    ) -> c_int;
    pub fn nqdinfer(
        dir: *const c_char,
        path: *const c_char,
        o: *const Csvopt,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
        why: *mut c_char,
        wcap: usize,
    ) -> c_int;
    pub fn nqdstats(
        dir: *const c_char,
        path: *const c_char,
        o: *const Csvopt,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
        why: *mut c_char,
        wcap: usize,
    ) -> c_int;
    pub fn nqddriftat(
        stats: *const c_char,
        n: usize,
        dir: *const c_char,
        path: *const c_char,
        o: *const Csvopt,
        d: *const Dopt,
        rep: *mut *mut Drep,
    ) -> c_int;
    pub fn nqdsha(dir: *const c_char, path: *const c_char, h: *mut u8, size: *mut u64) -> c_int;
    pub fn nqddiff(a: *const c_char, b: *const c_char, rep: *mut *mut Drep) -> c_int;
    pub fn nqdchk(dir: *const c_char, rep: *mut *mut Drep) -> c_int;
    pub fn nqdrepn(r: *const Drep) -> usize;
    pub fn nqdrepi(
        r: *const Drep,
        i: usize,
        check: *mut *const c_char,
        ok: *mut c_int,
        detail: *mut *const c_char,
    ) -> c_int;
    pub fn nqdrepj(r: *const Drep, i: usize) -> *const c_char;
    pub fn nqdrepfree(r: *mut Drep);
}

/// nqhctx, nqsctx, nqkfctx: contexts sized as noqtis.h sizes them
#[repr(C)]
pub struct Hctx {
    pub opq: [u64; 52],
}

#[repr(C)]
pub struct Sctx {
    pub opq: [u64; 160],
}

#[repr(C)]
pub struct Kfctx {
    pub opq: [u64; 16],
}

// the rest of include/noqtis.h a binding reaches
extern "C" {
    pub fn nqwipe(p: *mut u8, len: usize);
    pub fn nqcteq(a: *const u8, b: *const u8, len: usize) -> c_int;
    pub fn nqhini(c: *mut Hctx, alg: c_int) -> c_int;
    pub fn nqhupd(c: *mut Hctx, inp: *const u8, n: usize) -> c_int;
    pub fn nqhfin(c: *mut Hctx, out: *mut u8, n: usize) -> c_int;
    pub fn nqb2b(
        key: *const u8,
        kl: usize,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        ol: usize,
    ) -> c_int;
    pub fn nqkt(
        bits: std::os::raw::c_uint,
        inp: *const u8,
        n: usize,
        custom: *const u8,
        cl: usize,
        out: *mut u8,
        ol: usize,
    ) -> c_int;
    pub fn nqcha20(
        key: *const u8,
        kl: usize,
        nonce: *const u8,
        nl: usize,
        ctr: u32,
        inp: *const u8,
        n: usize,
        out: *mut u8,
    ) -> c_int;
    pub fn nqsivenc(
        key: *const u8,
        kl: usize,
        ad: *const *const u8,
        adl: *const usize,
        nad: usize,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        ol: usize,
    ) -> c_int;
    pub fn nqsivdec(
        key: *const u8,
        kl: usize,
        ad: *const *const u8,
        adl: *const usize,
        nad: usize,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        ol: usize,
    ) -> c_int;
    pub fn nqgsivenc(
        key: *const u8,
        kl: usize,
        nonce: *const u8,
        nl: usize,
        ad: *const u8,
        al: usize,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        ol: usize,
    ) -> c_int;
    pub fn nqgsivdec(
        key: *const u8,
        kl: usize,
        nonce: *const u8,
        nl: usize,
        ad: *const u8,
        al: usize,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        ol: usize,
    ) -> c_int;
    pub fn nqa2id(
        pw: *const u8,
        pwl: usize,
        salt: *const u8,
        sl: usize,
        key: *const u8,
        kl: usize,
        ad: *const u8,
        al: usize,
        t: u32,
        m: u32,
        p: u32,
        out: *mut u8,
        ol: usize,
    ) -> c_int;
    pub fn nqpwenc(
        pw: *const u8,
        pwl: usize,
        ad: *const u8,
        al: usize,
        m: u32,
        t: u32,
        p: u32,
        sk: *const u8,
        skl: usize,
        out: *mut u8,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqpwdec(
        pw: *const u8,
        pwl: usize,
        ad: *const u8,
        al: usize,
        inp: *const u8,
        n: usize,
        sk: *mut u8,
        cap: usize,
        skl: *mut usize,
    ) -> c_int;
    pub fn nqsmu(
        alg: c_int,
        pk: *const u8,
        pkl: usize,
        msg: *const u8,
        ml: usize,
        ctx: *const u8,
        cl: usize,
        ph: c_int,
        mu: *mut u8,
        mul: usize,
    ) -> c_int;
    pub fn nqsignmu(
        alg: c_int,
        sk: *const u8,
        skl: usize,
        mu: *const u8,
        mul: usize,
        rnd: *const u8,
        rl: usize,
        sig: *mut u8,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqvrfymu(
        alg: c_int,
        pk: *const u8,
        pkl: usize,
        mu: *const u8,
        mul: usize,
        sig: *const u8,
        sl: usize,
    ) -> c_int;
    pub fn nqsini(
        c: *mut Sctx,
        alg: c_int,
        sk: *const u8,
        skl: usize,
        ctx: *const u8,
        cl: usize,
        ph: c_int,
    ) -> c_int;
    pub fn nqvini(
        c: *mut Sctx,
        alg: c_int,
        pk: *const u8,
        pkl: usize,
        ctx: *const u8,
        cl: usize,
        ph: c_int,
    ) -> c_int;
    pub fn nqsupd(c: *mut Sctx, msg: *const u8, n: usize) -> c_int;
    pub fn nqsfin(
        c: *mut Sctx,
        sk: *const u8,
        skl: usize,
        rnd: *const u8,
        rl: usize,
        sig: *mut u8,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqvfin(c: *mut Sctx, pk: *const u8, pkl: usize, sig: *const u8, sl: usize) -> c_int;
    pub fn nqkseal(
        alg: c_int,
        pk: *const u8,
        pkl: usize,
        ctx: *const u8,
        cl: usize,
        msg: *const u8,
        n: usize,
        out: *mut u8,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqkopen(
        alg: c_int,
        sk: *const u8,
        skl: usize,
        ctx: *const u8,
        cl: usize,
        inp: *const u8,
        n: usize,
        msg: *mut u8,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqkfeini(
        c: *mut Kfctx,
        alg: c_int,
        pk: *const u8,
        pkl: usize,
        ctx: *const u8,
        cl: usize,
        chunk: u32,
        hdr: *mut u8,
        cap: usize,
        hl: *mut usize,
    ) -> c_int;
    pub fn nqkfdini(
        c: *mut Kfctx,
        alg: c_int,
        sk: *const u8,
        skl: usize,
        ctx: *const u8,
        cl: usize,
        hdr: *const u8,
        hl: usize,
        chunk: *mut u32,
    ) -> c_int;
    pub fn nqkfeupd(
        c: *mut Kfctx,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        cap: usize,
        ol: *mut usize,
    ) -> c_int;
    pub fn nqkfefin(
        c: *mut Kfctx,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        cap: usize,
        ol: *mut usize,
    ) -> c_int;
    pub fn nqkfdupd(
        c: *mut Kfctx,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        cap: usize,
        ol: *mut usize,
    ) -> c_int;
    pub fn nqkfdfin(
        c: *mut Kfctx,
        inp: *const u8,
        n: usize,
        out: *mut u8,
        cap: usize,
        ol: *mut usize,
    ) -> c_int;
    pub fn nqsealwhy(dir: *const c_char, why: *mut c_int, path: *mut c_char, cap: usize) -> c_int;
    pub fn nqtsreq(
        dir: *const c_char,
        nonce: *const u8,
        nl: usize,
        req: *mut u8,
        rl: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqtsput(
        dir: *const c_char,
        rsp: *const u8,
        rl: usize,
        nonce: *const u8,
        nl: usize,
        anc: *const *const u8,
        anclen: *const usize,
        nanc: usize,
        gt: *mut i64,
        why: *mut *const c_char,
    ) -> c_int;
    pub fn nqersreq(
        dir: *const c_char,
        h: c_int,
        nonce: *const u8,
        nl: usize,
        req: *mut u8,
        rl: usize,
        outlen: *mut usize,
        why: *mut *const c_char,
    ) -> c_int;
    pub fn nqersput(
        dir: *const c_char,
        h: c_int,
        rsp: *const u8,
        rl: usize,
        nonce: *const u8,
        nl: usize,
        anc: *const *const u8,
        anclen: *const usize,
        nanc: usize,
        gt: *mut i64,
        how: *mut c_int,
        why: *mut *const c_char,
    ) -> c_int;
    pub fn nqkstmt(
        alg: c_int,
        sk: *const u8,
        skl: usize,
        pk: *const u8,
        pkl: usize,
        nalg: c_int,
        nsk: *const u8,
        nskl: usize,
        npk: *const u8,
        npkl: usize,
        at: i64,
        reason: *const c_char,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqkexp(
        alg: c_int,
        sk: *const u8,
        skl: usize,
        pk: *const u8,
        pkl: usize,
        at: i64,
        reason: *const c_char,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdsse(
        alg: c_int,
        sk: *const u8,
        skl: usize,
        pk: *const u8,
        pkl: usize,
        typ: *const c_char,
        payload: *const u8,
        n: usize,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdssevrfy(
        alg: c_int,
        pk: *const u8,
        pkl: usize,
        env: *const c_char,
        n: usize,
        payload: *mut u8,
        cap: usize,
        outlen: *mut usize,
        typ: *mut c_char,
    ) -> c_int;
}

// the rest of include/nqd.h
extern "C" {
    pub fn nqdschk(
        dir: *const c_char,
        schema: *const c_char,
        n: usize,
        rep: *mut *mut Drep,
    ) -> c_int;
    pub fn nqdsyn(
        r: *mut Drec,
        dir: *const c_char,
        path: *const c_char,
        seed: u64,
        rows: u64,
        why: *mut c_char,
        wcap: usize,
    ) -> c_int;
    pub fn nqddcal(
        stats: *const c_char,
        n: usize,
        files: *const *const c_char,
        nf: usize,
        o: *const Csvopt,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
        why: *mut c_char,
        wcap: usize,
    ) -> c_int;
    pub fn nqdchunk(
        dir: *const c_char,
        path: *const c_char,
        chunk: u64,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
        why: *mut c_char,
        wcap: usize,
    ) -> c_int;
    pub fn nqdpiece(
        elem: *const c_char,
        n: usize,
        piece: *const c_char,
        off: u64,
        rep: *mut *mut Drep,
    ) -> c_int;
    pub fn nqdcommit(salt: *const u8, sl: usize, m: *const u8, n: usize, hex: *mut c_char)
        -> c_int;
    pub fn nqdreveal(
        r: *const Drec,
        salt: *const u8,
        sl: usize,
        m: *const u8,
        n: usize,
        idx: *mut usize,
    ) -> c_int;
    pub fn nqdcite(
        r: *const Drec,
        fmt: c_int,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdrpt(
        dir: *const c_char,
        crep: *const Rep,
        drep: *const Drep,
        fmt: c_int,
        out: *mut c_char,
        cap: usize,
        outlen: *mut usize,
    ) -> c_int;
    pub fn nqdpack(dir: *const c_char, files: c_int, file: *const c_char) -> c_int;
    pub fn nqdunpack(
        file: *const c_char,
        dir: *const c_char,
        rm: c_int,
        why: *mut c_char,
        cap: usize,
    ) -> c_int;
    pub fn nqdchain(
        dirs: *const *const c_char,
        n: usize,
        o: *const Copt,
        head: *mut u8,
        rep: *mut *mut Drep,
    ) -> c_int;
}
