# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake

DESCRIPTION="Post-quantum signing, KEMs and sealed input records in C11"
HOMEPAGE="https://github.com/rootcoder007/noqtis"
SRC_URI="https://github.com/rootcoder007/noqtis/releases/download/v${PV}/${P}.tar.gz"

LICENSE="Apache-2.0-with-LLVM-exceptions"
SLOT="0"
KEYWORDS="~amd64 ~arm64"
IUSE="test"
RESTRICT="!test? ( test )"

src_configure() {
	local mycmakeargs=(
		-DNQSHARED=ON
		-DNQWERROR=OFF
		-DNQOSSL=OFF
		-DNQTESTS=$(usex test)
	)
	cmake_src_configure
}

src_install() {
	cmake_src_install
	dodoc README.md NEWS.md
}
