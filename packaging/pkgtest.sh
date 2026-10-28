#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds one of the packaging/ recipes from a local source tarball, installs
# the package it makes and runs the consumer program against the installed
# package (pkg-config and find_package). Run from the source root:
#   packaging/pkgtest.sh arch|alpine|rpm|debian  as root, in that distro
#   packaging/pkgtest.sh brew                    where brew is (not root)
#   packaging/pkgtest.sh wolfi                   on a host with docker or
#                                                podman (NQOCI=podman)
# The tarball comes from packaging/tarball.sh unless NQTAR names one.
set -eu
kind=$1
root=$(pwd)
w=${NQWORK:-/tmp/nqpkg}
rm -rf "$w"
mkdir -p "$w"
tar=${NQTAR:-$(packaging/tarball.sh "$w")}
v=$(sed -n 's/^project(noqtis VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
sum=$(sha256sum "$tar" 2>/dev/null || shasum -a 256 "$tar")
sum=${sum%% *}
consumer() {
  sh "$root/tests/consumer/run.sh" "$1" "$w/use"
}

case $kind in
arch)
  pacman -Syu --noconfirm --needed base-devel cmake pkgconf
  id nqb >/dev/null 2>&1 || useradd -m nqb
  mkdir -p "$w/b"
  cp packaging/arch/PKGBUILD "$w/b/"
  cp "$tar" "$w/b/noqtis-$v.tar.gz"
  sed -i "s/^sha256sums=('SKIP')/sha256sums=('$sum')/" "$w/b/PKGBUILD"
  chown -R nqb "$w"
  su nqb -c "cd '$w/b' && makepkg --noconfirm"
  pacman -U --noconfirm "$w"/b/noqtis-"$v"-*.pkg.tar.*
  pacman -Ql noqtis
  consumer /usr
  ;;
alpine)
  apk add --no-cache alpine-sdk cmake samurai pkgconf
  abuild-keygen -a -n
  cp "$HOME"/.abuild/*.rsa.pub /etc/apk/keys/
  mkdir -p "$w/b"
  cp packaging/alpine/APKBUILD "$w/b/"
  # abuild takes a source already in SRCDEST instead of downloading it
  cp "$tar" "$w/b/noqtis-$v.tar.gz"
  (cd "$w/b" && export SRCDEST="$w/b" &&
    abuild -F checksum && abuild -F -P "$w/repo")
  apk add --no-cache --allow-untrusted "$w"/repo/*/*/noqtis-"$v"-*.apk \
    "$w"/repo/*/*/noqtis-dev-"$v"-*.apk
  apk info -L noqtis noqtis-dev
  consumer /usr
  ;;
rpm)
  dnf -y install rpm-build gcc cmake make pkgconf-pkg-config
  mkdir -p "$w/rpm/SOURCES"
  cp "$tar" "$w/rpm/SOURCES/noqtis-$v.tar.gz"
  rpmbuild --define "_topdir $w/rpm" -ba packaging/rpm/noqtis.spec
  dnf -y install "$w"/rpm/RPMS/*/noqtis-*.rpm
  rpm -ql noqtis noqtis-devel
  consumer /usr
  ;;
debian)
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential debhelper cmake pkgconf
  cp "$tar" "$w/noqtis_$v.orig.tar.gz"
  tar -C "$w" -xzf "$tar"
  cp -R packaging/debian "$w/noqtis-$v/debian"
  (cd "$w/noqtis-$v" && dpkg-buildpackage -us -uc -b)
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    "$w"/libnoqtis0_"$v"-*.deb "$w"/libnoqtis-dev_"$v"-*.deb
  dpkg -L libnoqtis0 libnoqtis-dev
  consumer /usr
  ;;
brew)
  # deps (cmake, pkgconf) come from the formula API, as for users
  export HOMEBREW_NO_AUTO_UPDATE=1
  export HOMEBREW_NO_ANALYTICS=1
  brew tap-new --no-git nqlocal/noqtis >/dev/null
  f=$(brew --repository nqlocal/noqtis)/Formula/noqtis.rb
  sed -e "s|^  url .*|  url \"file://$tar\"|" \
      -e "s|^  sha256 .*|  sha256 \"$sum\"|" packaging/brew/noqtis.rb > "$f"
  brew install --build-from-source --include-test --verbose \
    nqlocal/noqtis/noqtis
  brew test nqlocal/noqtis/noqtis
  brew audit --formula nqlocal/noqtis/noqtis || true
  consumer "$(brew --prefix noqtis)"
  brew uninstall noqtis
  brew untap nqlocal/noqtis
  ;;
wolfi)
  oci=${NQOCI:-docker}
  img=${NQMELANGE:?set NQMELANGE to the melange image}
  mkdir -p "$w/src"
  cp "$tar" "$w/src/noqtis-$v.tar.gz"
  # the fetch step becomes an unpack of the local tarball
  awk -v t="noqtis-$v.tar.gz" '
    /# nqsrc end/ { skip = 0; next }
    /# nqsrc:/ { skip = 1
      print "  - runs: tar -xzf " t " --strip-components=1 && rm " t
      next }
    skip != 1' packaging/wolfi/melange.yaml > "$w/melange.yaml"
  z=
  case $oci in *podman*) z=:Z ;; esac  # SELinux label for the mount
  "$oci" run --rm -u 0 -v "$w:/work$z" -w /work "$img" keygen
  "$oci" run --rm -u 0 --privileged -v "$w:/work$z" -w /work "$img" build \
    melange.yaml --arch "$(uname -m)" --source-dir src \
    --signing-key melange.rsa --out-dir packages
  "$oci" run --rm -u 0 --privileged -v "$w:/work$z" -w /work "$img" test \
    melange.yaml --arch "$(uname -m)" --source-dir src \
    --repository-append /work/packages --keyring-append melange.rsa.pub
  for a in "$w"/packages/*/*.apk; do
    echo "== $a"
    tar -tzf "$a" 2>/dev/null | grep -v '^\.' || true
  done
  ;;
*)
  echo "pkgtest.sh: unknown recipe $kind" >&2
  exit 2
  ;;
esac
echo "== $kind package ok"
