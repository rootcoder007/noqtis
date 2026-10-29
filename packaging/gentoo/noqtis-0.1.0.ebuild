# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Gentoo (an overlay, dev-libs/noqtis). For a release, rename the file to
# the new version and run `ebuild <file> manifest`.

EAPI=8

inherit cmake

DESCRIPTION="Post-quantum signing, KEMs and sealed input records in C11"
HOMEPAGE="https://github.com/rootcoder007/noqtis"
SRC_URI="https://github.com/rootcoder007/noqtis/archive/refs/tags/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0-with-LLVM-exceptions"
SLOT="0"
KEYWORDS="~amd64 ~arm64"
IUSE="test"
RESTRICT="!test? ( test )"

src_configure() {
	local mycmakeargs=(
		-DNQSHARED=ON
		-DNQWERROR=OFF
		-DNQTESTS=$(usex test)
	)
	cmake_src_configure
}

src_install() {
	cmake_src_install
	dodoc README.md NEWS.md
}
