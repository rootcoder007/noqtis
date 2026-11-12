// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// The host side of noqtis.wasm: the WASI preview 1 functions the C library
// (built with wasi-sdk) imports, over an in-memory file system that lives
// only in this object. Nothing here reaches the network, the host's files,
// its environment or its processes: the module sees one folder "/" that
// the wrapper fills with a capsule's files and empties after each call,
// no environment variables beyond the ones the C code sets itself, and
// randomness from crypto.getRandomValues, which it must be given. A
// function this host does not provide answers ENOSYS, so the library
// fails closed (randomness included: nqrand then returns NQERNG).

// errno values of WASI preview 1
const E = Object.freeze({
  SUCCESS: 0, BADF: 8, EXIST: 20, INVAL: 28, IO: 29, ISDIR: 31,
  NOENT: 44, NOSYS: 52, NOTDIR: 54, NOTEMPTY: 55, SPIPE: 70,
});

const DIR = 3; // filetype: directory
const REG = 4; // filetype: regular file

// oflags, fdflags, lookupflags, whence
const O_CREAT = 1;
const O_DIRECTORY = 2;
const O_EXCL = 4;
const O_TRUNC = 8;
const FD_APPEND = 1;

const RIGHTS = 0x1fffffffn; // every right preview 1 defines

const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;

const dec = new TextDecoder();
const enc = new TextEncoder();

class Err extends Error {
  constructor(code) {
    super(`wasi errno ${code}`);
    this.code = code;
  }
}

function fail(code) {
  throw new Err(code);
}

/**
 * Makes a host. `rand(view)` fills a Uint8Array with cryptographically
 * secure random bytes (crypto.getRandomValues, at most 65536 at a time)
 * or throws. Returns { imports, bind(memory), fs }.
 */
export function host(rand) {
  if (typeof rand !== 'function') {
    throw new TypeError('noqtis: a random source is required');
  }
  let mem = null;
  let ino = 0;
  const dirn = () => ({ type: DIR, kids: new Map(), ino: ++ino });
  const filen = () => ({
    type: REG, data: new Uint8Array(0), size: 0, ino: ++ino,
  });
  const root = dirn();
  // open files: fd -> { node, pos, append }; 3 is the preopened "/"
  const fds = new Map([[3, { node: root, pos: 0, append: false }]]);
  let nextfd = 4;

  const u8 = () => new Uint8Array(mem.buffer);
  const dv = () => new DataView(mem.buffer);
  const str = (p, n) => dec.decode(u8().subarray(p, p + n));

  // ---- the file system ----------------------------------------------------

  // The parts of a path below its base, with "." dropped and ".." taken
  // back; going above the base is NOENT, so nothing escapes the root.
  function parts(path) {
    const out = [];
    for (const s of path.split('/')) {
      if (s === '' || s === '.') continue;
      if (s === '..') {
        if (out.length === 0) fail(E.NOENT);
        out.pop();
      } else {
        out.push(s);
      }
    }
    return out;
  }

  // The folder holding the last part of path, and that part's name.
  function parent(base, path) {
    const p = parts(path);
    if (p.length === 0) return { dir: null, name: '', node: base };
    let d = base;
    for (const s of p.slice(0, -1)) {
      if (d.type !== DIR) fail(E.NOTDIR);
      d = d.kids.get(s);
      if (d === undefined) fail(E.NOENT);
    }
    if (d.type !== DIR) fail(E.NOTDIR);
    const name = p[p.length - 1];
    return { dir: d, name, node: d.kids.get(name) };
  }

  function lookup(base, path) {
    const r = parent(base, path);
    if (r.node === undefined) fail(E.NOENT);
    return r.node;
  }

  function fdget(fd) {
    const f = fds.get(fd);
    if (f === undefined) fail(E.BADF);
    return f;
  }

  function dirfd(fd) {
    const f = fdget(fd);
    if (f.node.type !== DIR) fail(E.NOTDIR);
    return f.node;
  }

  function grow(node, n) {
    if (n <= node.data.length) return;
    const d = new Uint8Array(Math.max(n, node.data.length * 2, 64));
    d.set(node.data.subarray(0, node.size));
    node.data = d;
  }

  function filestat(p, node) {
    const v = dv();
    for (let i = 0; i < 64; i += 8) v.setBigUint64(p + i, 0n, true);
    v.setBigUint64(p + 8, BigInt(node.ino), true);
    v.setUint8(p + 16, node.type);
    v.setBigUint64(p + 24, 1n, true);
    v.setBigUint64(p + 32, BigInt(node.type === REG ? node.size : 0), true);
  }

  // Runs f; a thrown Err is its errno, anything else is a bug and stays
  // thrown (the call traps, nothing continues on a half-done state).
  const w = (f) => (...a) => {
    try {
      return f(...a) ?? E.SUCCESS;
    } catch (e) {
      if (e instanceof Err) return e.code;
      throw e;
    }
  };

  // no arguments and no environment: a count of 0 and 0 bytes
  const none = (pc, ps) => {
    const v = dv();
    v.setUint32(pc, 0, true);
    v.setUint32(ps, 0, true);
  };

  const imports = {
    args_sizes_get: w(none),
    args_get: w(() => {}),
    environ_sizes_get: w(none),
    environ_get: w(() => {}),

    clock_res_get: w((id, p) => {
      dv().setBigUint64(p, 1000n, true);
    }),
    clock_time_get: w((id, precision, p) => {
      let t;
      if (id === 0) {
        t = BigInt(Date.now()) * 1000000n;
      } else if (id === 1) {
        t = BigInt(Math.round(performance.now() * 1e6));
      } else {
        fail(E.INVAL);
      }
      dv().setBigUint64(p, t, true);
    }),

    // getentropy() and so nqrand(): crypto.getRandomValues or an error,
    // never anything weaker
    random_get: w((p, n) => {
      const b = u8().subarray(p, p + n);
      try {
        for (let i = 0; i < n; i += 65536) {
          rand(b.subarray(i, Math.min(n, i + 65536)));
        }
      } catch (e) {
        b.fill(0);
        fail(E.IO);
      }
    }),

    fd_prestat_get: w((fd, p) => {
      if (fd !== 3) fail(E.BADF);
      const v = dv();
      v.setUint32(p, 0, true); // tag 0: a folder
      v.setUint32(p + 4, 1, true); // "/"
    }),
    fd_prestat_dir_name: w((fd, p, n) => {
      if (fd !== 3) fail(E.BADF);
      if (n < 1) fail(E.INVAL);
      u8()[p] = 0x2f;
    }),

    fd_fdstat_get: w((fd, p) => {
      const v = dv();
      if (fd <= 2) {
        v.setUint8(p, 2); // character device
        v.setUint16(p + 2, 0, true);
      } else {
        const f = fdget(fd);
        v.setUint8(p, f.node.type);
        v.setUint16(p + 2, f.append ? FD_APPEND : 0, true);
      }
      v.setBigUint64(p + 8, RIGHTS, true);
      v.setBigUint64(p + 16, RIGHTS, true);
    }),
    fd_fdstat_set_flags: w((fd, flags) => {
      if (fd <= 2) return;
      fdget(fd).append = (flags & FD_APPEND) !== 0;
    }),

    fd_close: w((fd) => {
      if (fd <= 3) return;
      fdget(fd);
      fds.delete(fd);
    }),
    fd_sync: w((fd) => {
      if (fd > 2) fdget(fd);
    }),
    fd_datasync: w((fd) => {
      if (fd > 2) fdget(fd);
    }),

    fd_read: w((fd, iov, n, pn) => {
      if (fd <= 2) {
        dv().setUint32(pn, 0, true);
        return;
      }
      const f = fdget(fd);
      if (f.node.type !== REG) fail(E.ISDIR);
      const v = dv();
      let got = 0;
      for (let i = 0; i < n; i++) {
        const b = v.getUint32(iov + 8 * i, true);
        const l = v.getUint32(iov + 8 * i + 4, true);
        const k = Math.max(0, Math.min(l, f.node.size - f.pos));
        u8().set(f.node.data.subarray(f.pos, f.pos + k), b);
        f.pos += k;
        got += k;
        if (k < l) break;
      }
      v.setUint32(pn, got, true);
    }),

    fd_write: w((fd, iov, n, pn) => {
      const v = dv();
      let put = 0;
      if (fd <= 2) { // stdout and stderr are dropped, as before
        for (let i = 0; i < n; i++) put += v.getUint32(iov + 8 * i + 4, true);
        v.setUint32(pn, put, true);
        return;
      }
      const f = fdget(fd);
      if (f.node.type !== REG) fail(E.ISDIR);
      if (f.append) f.pos = f.node.size;
      for (let i = 0; i < n; i++) {
        const b = v.getUint32(iov + 8 * i, true);
        const l = v.getUint32(iov + 8 * i + 4, true);
        grow(f.node, f.pos + l);
        f.node.data.set(u8().subarray(b, b + l), f.pos);
        f.pos += l;
        if (f.pos > f.node.size) f.node.size = f.pos;
        put += l;
      }
      v.setUint32(pn, put, true);
    }),

    fd_seek: w((fd, off, whence, p) => {
      if (fd <= 2) fail(E.SPIPE);
      const f = fdget(fd);
      const o = Number(off);
      let to;
      if (whence === 0) to = o;
      else if (whence === 1) to = f.pos + o;
      else if (whence === 2) to = (f.node.size ?? 0) + o;
      else fail(E.INVAL);
      if (!Number.isSafeInteger(to) || to < 0) fail(E.INVAL);
      f.pos = to;
      dv().setBigUint64(p, BigInt(to), true);
    }),
    fd_tell: w((fd, p) => {
      if (fd <= 2) fail(E.SPIPE);
      dv().setBigUint64(p, BigInt(fdget(fd).pos), true);
    }),

    fd_filestat_get: w((fd, p) => {
      if (fd <= 2) {
        filestat(p, { type: 2, ino: 0, size: 0 });
        return;
      }
      filestat(p, fdget(fd).node);
    }),
    fd_filestat_set_size: w((fd, size) => {
      const f = fdget(fd);
      if (f.node.type !== REG) fail(E.ISDIR);
      const n = Number(size);
      if (!Number.isSafeInteger(n) || n < 0) fail(E.INVAL);
      grow(f.node, n);
      if (n > f.node.size) f.node.data.fill(0, f.node.size, n);
      f.node.size = n;
    }),
    fd_filestat_set_times: w((fd) => {
      fdget(fd);
    }),

    fd_readdir: w((fd, buf, len, cookie, pused) => {
      const d = dirfd(fd);
      const names = ['.', '..', ...[...d.kids.keys()].sort()];
      const v = dv();
      let used = 0;
      for (let i = Number(cookie); i < names.length && used < len; i++) {
        const nb = enc.encode(names[i]);
        const node = i < 2 ? d : d.kids.get(names[i]);
        const ent = new Uint8Array(24 + nb.length);
        const ev = new DataView(ent.buffer);
        ev.setBigUint64(0, BigInt(i + 1), true);
        ev.setBigUint64(8, BigInt(node.ino), true);
        ev.setUint32(16, nb.length, true);
        ev.setUint8(20, node.type);
        ent.set(nb, 24);
        // a last entry that does not fit is cut short, as WASI wants
        const k = Math.min(ent.length, len - used);
        u8().set(ent.subarray(0, k), buf + used);
        used += k;
      }
      v.setUint32(pused, used, true);
    }),

    path_open: w((fd, dirflags, p, n, oflags, rbase, rinh, fdflags, pfd) => {
      const base = dirfd(fd);
      const r = parent(base, str(p, n));
      let node = r.node;
      if (node === undefined) {
        if ((oflags & O_CREAT) === 0 || r.dir === null) fail(E.NOENT);
        if ((oflags & O_DIRECTORY) !== 0) fail(E.INVAL);
        node = filen();
        r.dir.kids.set(r.name, node);
      } else {
        if ((oflags & O_CREAT) !== 0 && (oflags & O_EXCL) !== 0) fail(E.EXIST);
        if ((oflags & O_DIRECTORY) !== 0 && node.type !== DIR) fail(E.NOTDIR);
        if ((oflags & O_TRUNC) !== 0) {
          if (node.type !== REG) fail(E.ISDIR);
          node.size = 0;
          node.data = new Uint8Array(0);
        }
      }
      const f = nextfd++;
      fds.set(f, { node, pos: 0, append: (fdflags & FD_APPEND) !== 0 });
      dv().setUint32(pfd, f, true);
    }),

    path_filestat_get: w((fd, flags, p, n, buf) => {
      filestat(buf, lookup(dirfd(fd), str(p, n)));
    }),
    path_filestat_set_times: w((fd, flags, p, n) => {
      lookup(dirfd(fd), str(p, n));
    }),

    path_create_directory: w((fd, p, n) => {
      const r = parent(dirfd(fd), str(p, n));
      if (r.dir === null || r.node !== undefined) fail(E.EXIST);
      r.dir.kids.set(r.name, dirn());
    }),
    path_remove_directory: w((fd, p, n) => {
      const r = parent(dirfd(fd), str(p, n));
      if (r.node === undefined) fail(E.NOENT);
      if (r.dir === null || r.node.type !== DIR) fail(E.NOTDIR);
      if (r.node.kids.size > 0) fail(E.NOTEMPTY);
      r.dir.kids.delete(r.name);
    }),
    path_unlink_file: w((fd, p, n) => {
      const r = parent(dirfd(fd), str(p, n));
      if (r.node === undefined) fail(E.NOENT);
      if (r.dir === null || r.node.type === DIR) fail(E.ISDIR);
      r.dir.kids.delete(r.name);
    }),
    path_rename: w((fd, p, n, fd2, p2, n2) => {
      const a = parent(dirfd(fd), str(p, n));
      const b = parent(dirfd(fd2), str(p2, n2));
      if (a.node === undefined) fail(E.NOENT);
      if (a.dir === null || b.dir === null) fail(E.INVAL);
      if (b.node !== undefined) {
        if (b.node.type === DIR) {
          if (a.node.type !== DIR) fail(E.ISDIR);
          if (b.node.kids.size > 0) fail(E.NOTEMPTY);
        } else if (a.node.type === DIR) {
          fail(E.NOTDIR);
        }
      }
      a.dir.kids.delete(a.name);
      b.dir.kids.set(b.name, a.node);
    }),
    // no links in this file system
    path_readlink: w(() => fail(E.INVAL)),
    path_symlink: w(() => fail(E.NOSYS)),
    path_link: w(() => fail(E.NOSYS)),

    sched_yield: w(() => {}),
    proc_exit: (code) => {
      throw new Error(`noqtis: the WebAssembly module exited (${code})`);
    },
  };

  // every other preview 1 function: ENOSYS
  for (const n of ['fd_advise', 'fd_allocate', 'fd_fdstat_set_rights',
    'fd_pread', 'fd_pwrite', 'fd_renumber', 'poll_oneoff', 'proc_raise',
    'sock_accept', 'sock_recv', 'sock_send', 'sock_shutdown']) {
    imports[n] = () => E.NOSYS;
  }

  // ---- what the wrapper uses (the subset of emscripten's FS it called) --

  const node = (path) => lookup(root, path);
  const fs = {
    mkdir(path) {
      const r = parent(root, path);
      if (r.dir === null || r.node !== undefined) {
        throw new Error(`${path} exists`);
      }
      r.dir.kids.set(r.name, dirn());
    },
    writeFile(path, data) {
      const r = parent(root, path);
      if (r.dir === null || (r.node !== undefined && r.node.type === DIR)) {
        throw new Error(`${path} is a folder`);
      }
      const f = filen();
      f.data = Uint8Array.from(data);
      f.size = f.data.length;
      r.dir.kids.set(r.name, f);
    },
    readFile(path) {
      const n = node(path);
      if (n.type !== REG) throw new Error(`${path} is a folder`);
      return n.data.slice(0, n.size);
    },
    readdir(path) {
      const n = node(path);
      if (n.type !== DIR) throw new Error(`${path} is not a folder`);
      return ['.', '..', ...[...n.kids.keys()].sort()];
    },
    lstat(path) {
      const n = node(path);
      return { mode: n.type === DIR ? S_IFDIR | 0o755 : S_IFREG | 0o644 };
    },
    isDir(mode) {
      return (mode & 0o170000) === S_IFDIR;
    },
    rmdir(path) {
      const r = parent(root, path);
      if (r.node === undefined || r.node.type !== DIR || r.node.kids.size > 0) {
        throw new Error(`cannot remove ${path}`);
      }
      r.dir.kids.delete(r.name);
    },
    unlink(path) {
      const r = parent(root, path);
      if (r.node === undefined || r.node.type === DIR) {
        throw new Error(`cannot remove ${path}`);
      }
      // the bytes are cleared: a capsule's files leave no copy behind
      r.node.data.fill(0);
      r.dir.kids.delete(r.name);
    },
    analyzePath(path) {
      try {
        const n = node(path);
        const mode = this.lstat(path).mode;
        return { exists: true, object: { mode, ino: n.ino } };
      } catch (e) {
        if (e instanceof Err) return { exists: false, object: null };
        throw e;
      }
    },
  };

  return {
    imports,
    fs,
    bind(memory) {
      if (!(memory instanceof WebAssembly.Memory)) {
        throw new TypeError('noqtis: the module exports no memory');
      }
      mem = memory;
    },
  };
}
