// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The WASI host (lib/wasi.js) on its own, against a memory laid out as
// wasi-libc lays out its arguments: files, folders, offsets, listings,
// renames, the root it cannot leave, and randomness that fails closed.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { host } from '../lib/wasi.js';

const mk = (rand = (v) => globalThis.crypto.getRandomValues(v)) => {
  const h = host(rand);
  const mem = new WebAssembly.Memory({ initial: 2 });
  h.bind(mem);
  const u8 = () => new Uint8Array(mem.buffer);
  const dv = () => new DataView(mem.buffer);
  const enc = new TextEncoder();
  let top = 1024;
  const put = (b) => {
    const p = top;
    u8().set(b, p);
    top += b.length + 8;
    return p;
  };
  const str = (s) => {
    const b = enc.encode(s);
    return [put(b), b.length];
  };
  return { h, w: h.imports, u8, dv, put, str, out: 16, iov: 64 };
};

const open = (t, path, oflags = 0, fdflags = 0) => {
  const [p, n] = t.str(path);
  const rc = t.w.path_open(3, 0, p, n, oflags, 0n, 0n, fdflags, t.out);
  return [rc, t.dv().getUint32(t.out, true)];
};

const write = (t, fd, bytes) => {
  const p = t.put(bytes);
  t.dv().setUint32(t.iov, p, true);
  t.dv().setUint32(t.iov + 4, bytes.length, true);
  const rc = t.w.fd_write(fd, t.iov, 1, t.out);
  return [rc, t.dv().getUint32(t.out, true)];
};

const read = (t, fd, n) => {
  const p = t.put(new Uint8Array(n));
  t.dv().setUint32(t.iov, p, true);
  t.dv().setUint32(t.iov + 4, n, true);
  const rc = t.w.fd_read(fd, t.iov, 1, t.out);
  const got = t.dv().getUint32(t.out, true);
  return [rc, t.u8().slice(p, p + got)];
};

test('the root is preopened as / and nothing else is', () => {
  const t = mk();
  assert.equal(t.w.fd_prestat_get(3, t.out), 0);
  assert.equal(t.dv().getUint32(t.out + 4, true), 1);
  assert.equal(t.w.fd_prestat_dir_name(3, t.out, 1), 0);
  assert.equal(t.u8()[t.out], 0x2f);
  assert.equal(t.w.fd_prestat_get(4, t.out), 8); // BADF ends the scan
});

test('files: create, write, seek, read, truncate, exclusive', () => {
  const t = mk();
  const [rc, fd] = open(t, 'a.txt', 1);
  assert.equal(rc, 0);
  assert.deepEqual(write(t, fd, new TextEncoder().encode('hello')), [0, 5]);
  assert.equal(t.w.fd_seek(fd, 1n, 0, t.out), 0);
  assert.equal(t.dv().getBigUint64(t.out, true), 1n);
  const [r1, b1] = read(t, fd, 10);
  assert.equal(r1, 0);
  assert.equal(new TextDecoder().decode(b1), 'ello');
  assert.equal(t.w.fd_seek(fd, -2n, 2, t.out), 0);
  assert.equal(t.dv().getBigUint64(t.out, true), 3n);
  assert.equal(t.w.fd_seek(fd, -9n, 1, t.out), 28); // INVAL: before 0
  assert.equal(t.w.fd_filestat_get(fd, t.out), 0);
  assert.equal(t.dv().getUint8(t.out + 16), 4);
  assert.equal(t.dv().getBigUint64(t.out + 32, true), 5n);
  assert.equal(t.w.fd_close(fd), 0);
  assert.equal(t.w.fd_close(fd), 8);
  assert.equal(open(t, 'a.txt', 1 | 4)[0], 20); // CREAT|EXCL: EXIST
  const [, fd2] = open(t, 'a.txt', 8); // TRUNC
  assert.equal(t.w.fd_filestat_get(fd2, t.out), 0);
  assert.equal(t.dv().getBigUint64(t.out + 32, true), 0n);
  assert.equal(open(t, 'none')[0], 44);
  assert.equal(t.h.fs.readFile('/a.txt').length, 0);
});

test('append mode writes at the end', () => {
  const t = mk();
  t.h.fs.writeFile('/log', new Uint8Array([1, 2]));
  const [, fd] = open(t, 'log', 0, 1);
  write(t, fd, new Uint8Array([3]));
  assert.deepEqual([...t.h.fs.readFile('/log')], [1, 2, 3]);
});

test('folders: listing in pieces, stat, remove, rename', () => {
  const t = mk();
  t.h.fs.mkdir('/d');
  t.h.fs.writeFile('/d/b', new Uint8Array(3));
  t.h.fs.writeFile('/d/a', new Uint8Array(2));
  const [rc, fd] = open(t, 'd', 2);
  assert.equal(rc, 0);
  const names = [];
  let cookie = 0n;
  for (;;) { // a small buffer: entries arrive cut short and are re-read
    const buf = t.put(new Uint8Array(40));
    assert.equal(t.w.fd_readdir(fd, buf, 40, cookie, t.out), 0);
    const used = t.dv().getUint32(t.out, true);
    if (used < 24) break;
    const nl = t.dv().getUint32(buf + 16, true);
    if (24 + nl > used) break;
    names.push(new TextDecoder().decode(t.u8().slice(buf + 24, buf + 24 + nl)));
    cookie = t.dv().getBigUint64(buf, true);
    if (used < 40 && 24 + nl === used) {
      // only one entry fitted and the buffer was not full: the end
      if (cookie >= 4n) break;
    }
  }
  assert.deepEqual(names, ['.', '..', 'a', 'b']);
  const [p, n] = t.str('d/a');
  assert.equal(t.w.path_filestat_get(3, 0, p, n, t.out), 0);
  assert.equal(t.dv().getBigUint64(t.out + 32, true), 2n);
  const [q, m] = t.str('d');
  assert.equal(t.w.path_remove_directory(3, q, m), 55); // NOTEMPTY
  const [r, k] = t.str('d/c');
  assert.equal(t.w.path_rename(3, p, n, 3, r, k), 0);
  assert.deepEqual(t.h.fs.readdir('/d'), ['.', '..', 'b', 'c']);
  assert.equal(t.w.path_unlink_file(3, r, k), 0);
  assert.equal(t.w.path_unlink_file(3, q, m), 31); // a folder: ISDIR
  assert.equal(t.h.fs.analyzePath('/d/c').exists, false);
  assert.equal(t.h.fs.isDir(t.h.fs.lstat('/d').mode), true);
});

test('paths cannot leave the root', () => {
  const t = mk();
  t.h.fs.mkdir('/d');
  assert.equal(open(t, '../x', 1)[0], 44);
  assert.equal(open(t, 'd/../../x', 1)[0], 44);
  assert.equal(open(t, 'd/../y', 1)[0], 0);
  assert.equal(t.h.fs.analyzePath('/y').exists, true);
});

test('randomness is crypto.getRandomValues or an error, never weaker', () => {
  let calls = 0;
  const t = mk((v) => {
    calls++;
    globalThis.crypto.getRandomValues(v);
  });
  const p = t.put(new Uint8Array(100000));
  assert.equal(t.w.random_get(p, 100000), 0);
  assert.equal(calls, 2); // at most 65536 bytes per call
  assert.ok(t.u8().slice(p, p + 100000).some((b) => b !== 0));
  const bad = mk(() => {
    throw new Error('no entropy');
  });
  const q = bad.put(new Uint8Array(32).fill(7));
  assert.equal(bad.w.random_get(q, 32), 29); // EIO: getentropy fails
  assert.ok(bad.u8().slice(q, q + 32).every((b) => b === 0));
  assert.throws(() => host(undefined), TypeError);
});

test('no environment, no arguments, no network, no other host calls', () => {
  const t = mk();
  assert.equal(t.w.environ_sizes_get(t.out, t.out + 4), 0);
  assert.equal(t.dv().getUint32(t.out, true), 0);
  assert.equal(t.w.args_sizes_get(t.out, t.out + 4), 0);
  assert.equal(t.dv().getUint32(t.out, true), 0);
  for (const f of ['sock_accept', 'sock_recv', 'sock_send', 'poll_oneoff',
    'path_symlink', 'path_link', 'fd_pwrite']) {
    assert.equal(t.w[f](0, 0, 0, 0, 0, 0), 52, f); // ENOSYS
  }
  assert.throws(() => t.w.proc_exit(3), /exited \(3\)/);
  assert.equal(t.w.clock_time_get(0, 0n, t.out), 0);
  const ns = t.dv().getBigUint64(t.out, true);
  assert.ok(ns > 1700000000n * 1000000000n);
});

test('the wrapper\'s file calls: unlink clears the bytes', () => {
  const t = mk();
  t.h.fs.mkdir('/c');
  const data = new Uint8Array([9, 9, 9]);
  t.h.fs.writeFile('/c/f', data);
  const kept = t.h.fs.readFile('/c/f');
  t.h.fs.unlink('/c/f');
  t.h.fs.rmdir('/c');
  assert.deepEqual([...kept], [9, 9, 9]); // a copy was returned
  assert.equal(t.h.fs.analyzePath('/c').exists, false);
  assert.throws(() => t.h.fs.mkdir('/'), /exists/);
});
