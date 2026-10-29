#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Installs the noqtis command, library, header and manual pages from a
# GitHub release of rootcoder007/noqtis, on Linux and macOS.
#
#   curl -fsSL https://github.com/rootcoder007/noqtis/releases/latest/download/install.sh | sh
#   sh install.sh [--prefix DIR] [--version X.Y.Z] [--shared]
#
# What it does, in order, stopping at the first failure:
#   1. picks the archive for this OS and CPU (linux or macos, x86_64 or
#      arm64; on Linux the static build unless --shared);
#   2. downloads the release's SHA256SUMS and, when cosign is installed,
#      checks its Sigstore signature: signed by this repository's release
#      workflow for that very tag (without cosign it says so and goes on);
#   3. downloads the archive and checks its SHA-256 against SHA256SUMS;
#   4. checks every path in the archive stays inside its top directory;
#   5. copies bin/, include/, lib/ and share/ into the prefix.
# Nothing from the archive runs before step 3 passes, and nothing is
# installed if any step fails. It never calls sudo: pick a prefix you can
# write to.
#
# Environment (the options win):
#   NOQTIS_PREFIX   where to install (default: $HOME/.local)
#   NOQTIS_VERSION  a release such as 0.1.0 (default: the latest release)
#   NOQTIS_SHARED   1 for the shared-library archive (Linux only)
#   NOQTIS_COSIGN   auto (default): check with cosign when it is installed;
#                   1: require cosign; 0: skip the Sigstore check
#   NOQTIS_BASE     the releases URL (default:
#                   https://github.com/rootcoder007/noqtis/releases); only
#                   https, or http to localhost for testing
#
# The whole script is one function called on its last line, so a download
# cut short runs nothing.
set -eu

nqrepo=rootcoder007/noqtis
nqissuer=https://token.actions.githubusercontent.com

say() { printf 'noqtis install: %s\n' "$*" >&2; }
die() {
  say "error: $*"
  if [ "${nqcopied:-0}" = 1 ]; then
    say "the install into the prefix may be incomplete"
  else
    say "nothing was installed"
  fi
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: sh install.sh [--prefix DIR] [--version X.Y.Z] [--shared]
options: --prefix DIR  --version X.Y.Z  --shared  --help
environment: NOQTIS_PREFIX NOQTIS_VERSION NOQTIS_SHARED NOQTIS_COSIGN NOQTIS_BASE
EOF
}

fetch() { # fetch <url> <file>
  case $1 in
    https://*)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
      elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$2" "$1"
      else
        die "neither curl nor wget is installed"
      fi ;;
    *)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
      elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
      else
        die "neither curl nor wget is installed"
      fi ;;
  esac
}

sha256() { # prints the lowercase hex SHA-256 of a file
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$1" | awk '{print $1}'
  else
    die "no sha256sum, shasum or openssl to check the download with"
  fi
}

nqmain() {
  prefix=${NOQTIS_PREFIX:-}
  ver=${NOQTIS_VERSION:-}
  shared=${NOQTIS_SHARED:-0}
  sigmode=${NOQTIS_COSIGN:-auto}
  base=${NOQTIS_BASE:-https://github.com/$nqrepo/releases}
  while [ $# -gt 0 ]; do
    case $1 in
      --prefix) [ $# -ge 2 ] || die "--prefix needs a directory"
                prefix=$2; shift 2 ;;
      --prefix=*) prefix=${1#--prefix=}; shift ;;
      --version) [ $# -ge 2 ] || die "--version needs a version"
                 ver=$2; shift 2 ;;
      --version=*) ver=${1#--version=}; shift ;;
      --shared) shared=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage; die "unknown option: $1" ;;
    esac
  done
  if [ -z "$prefix" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set; give --prefix"
    prefix=$HOME/.local
  fi
  ver=${ver#v}
  if [ -n "$ver" ] &&
     ! printf '%s\n' "$ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
  then
    die "not a release version: $ver"
  fi
  case $sigmode in auto|0|1) ;; *) die "NOQTIS_COSIGN must be auto, 0 or 1" ;; esac
  base=${base%/}
  case $base in
    https://*) ;;
    http://127.0.0.1:*|http://127.0.0.1/*|http://localhost:*|http://localhost/*) ;;
    *) die "NOQTIS_BASE must be an https URL (or http to localhost): $base" ;;
  esac

  # 1. the archive for this machine
  case $(uname -s) in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      die "on Windows use install.ps1 (see the install page)" ;;
    *) die "no release archive for $(uname -s); build from source" ;;
  esac
  case $(uname -m) in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "no release archive for the $(uname -m) CPU; build from source" ;;
  esac
  # an x86-64 shell under Rosetta on Apple silicon: take the native build
  if [ "$os" = macos ] && [ "$arch" = x86_64 ] &&
     [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    arch=arm64
  fi
  target=$os-$arch
  if [ "$shared" = 1 ]; then
    [ "$os" = linux ] || die "the shared-library archive is built for Linux only"
    target=$target-shared
  fi

  if [ -n "$ver" ]; then
    url=$base/download/v$ver
  else
    url=$base/latest/download
  fi

  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t noqtis)
  [ -n "$tmp" ] && [ -d "$tmp" ] || die "cannot make a temporary directory"
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 1' INT TERM HUP

  # 2. the sums, and their signature
  say "fetching $url/SHA256SUMS"
  fetch "$url/SHA256SUMS" "$tmp/SHA256SUMS" || die "cannot download SHA256SUMS"
  names=$(awk '{f=$2; sub(/^\*/, "", f); print f}' "$tmp/SHA256SUMS" |
    grep -E "^noqtis-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?-$target\.tar\.gz\$" || true)
  if [ -n "$ver" ]; then
    name=noqtis-$ver-$target.tar.gz
    printf '%s\n' "$names" | grep -qxF "$name" ||
      die "SHA256SUMS of v$ver lists no $name"
  else
    [ -n "$names" ] || die "the latest release lists no archive for $target"
    [ "$(printf '%s\n' "$names" | wc -l | tr -d ' ')" = 1 ] ||
      die "SHA256SUMS lists more than one archive for $target"
    name=$names
    ver=${name#noqtis-}
    ver=${ver%-"$target".tar.gz}
  fi
  want=$(awk -v n="$name" '{f=$2; sub(/^\*/, "", f); if (f == n) print tolower($1)}' \
    "$tmp/SHA256SUMS")
  printf '%s\n' "$want" | grep -Eqx '[0-9a-f]{64}' ||
    die "SHA256SUMS has no single valid SHA-256 for $name"

  if [ "$sigmode" = 0 ]; then
    say "NOQTIS_COSIGN=0: the Sigstore signature of SHA256SUMS is NOT checked"
  elif command -v cosign >/dev/null 2>&1; then
    say "checking the Sigstore signature of SHA256SUMS with cosign"
    fetch "$url/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS.sigstore.json" ||
      die "cosign is installed but SHA256SUMS.sigstore.json cannot be downloaded"
    cosign verify-blob --bundle "$tmp/SHA256SUMS.sigstore.json" \
      --certificate-identity \
      "https://github.com/$nqrepo/.github/workflows/release.yml@refs/tags/v$ver" \
      --certificate-oidc-issuer "$nqissuer" "$tmp/SHA256SUMS" >&2 ||
      die "the Sigstore signature of SHA256SUMS does not verify"
    say "Sigstore signature: good (release workflow of $nqrepo, tag v$ver)"
  elif [ "$sigmode" = 1 ]; then
    die "NOQTIS_COSIGN=1 but cosign is not installed"
  else
    say "cosign not found: the Sigstore signature of SHA256SUMS is NOT checked"
    say "(the archive is still checked against SHA256SUMS; install cosign, or"
    say "set NOQTIS_COSIGN=1 to require the signature check)"
  fi

  # 3. the archive, checked before anything else touches it
  say "fetching $url/$name"
  fetch "$url/$name" "$tmp/$name" || die "cannot download $name"
  got=$(sha256 "$tmp/$name")
  if [ "$got" != "$want" ]; then
    say "SHA256SUMS says $want"
    say "the download is $got"
    die "SHA-256 mismatch for $name"
  fi
  say "SHA-256 of $name matches SHA256SUMS"

  # 4. every entry inside noqtis-<version>-<target>/, no absolute or ..
  top=noqtis-$ver-$target
  tar -tzf "$tmp/$name" > "$tmp/list" || die "cannot read $name"
  bad=$(grep -Ev "^$top(/|\$)" "$tmp/list" || true)
  [ -z "$bad" ] || die "$name has entries outside $top/"
  if grep -Eq '(^|/)\.\.(/|$)' "$tmp/list"; then
    die "$name has a .. path"
  fi
  mkdir "$tmp/x"
  tar -xzf "$tmp/$name" -C "$tmp/x" || die "cannot unpack $name"
  [ -f "$tmp/x/$top/bin/noqtis" ] || die "$name has no bin/noqtis"

  # 5. into the prefix: the library, header and pages first, the command last
  mkdir -p "$prefix" 2>/dev/null && [ -w "$prefix" ] ||
    die "cannot write to $prefix; choose another with --prefix or NOQTIS_PREFIX (this script never uses sudo)"
  nqcopied=1
  for d in include lib share bin; do
    if [ -d "$tmp/x/$top/$d" ]; then
      mkdir -p "$prefix/$d"
      cp -RP "$tmp/x/$top/$d/." "$prefix/$d/" || die "copy into $prefix/$d failed"
    fi
  done
  say "installed noqtis $ver ($target) into $prefix"
  "$prefix/bin/noqtis" version >&2 || die "the installed noqtis does not run"
  case ":${PATH:-}:" in
    *":$prefix/bin:"*) ;;
    *) say "add $prefix/bin to PATH, for example:"
       say "  export PATH=\"$prefix/bin:\$PATH\"" ;;
  esac
}

nqmain "$@"
