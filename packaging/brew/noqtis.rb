# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Homebrew formula (macOS and Linux). For a release, set url and sha256 to
# the tagged tarball; `brew install --HEAD` builds main.
class Noqtis < Formula
  desc "Post-quantum signing, KEMs and sealed input records in C11"
  homepage "https://github.com/rootcoder007/noqtis"
  url "https://github.com/rootcoder007/noqtis/archive/refs/tags/v0.1.1.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0" => { with: "LLVM-exception" }
  head "https://github.com/rootcoder007/noqtis.git", branch: "main"

  depends_on "cmake" => [:build, :test]
  depends_on "pkgconf" => :test

  def install
    system "cmake", "-S", ".", "-B", "build", "-DNQSHARED=ON",
           "-DNQWERROR=OFF", *std_cmake_args
    system "cmake", "--build", "build"
    system "ctest", "--test-dir", "build", "--output-on-failure"
    system "cmake", "--install", "build"
    pkgshare.install "tests/consumer"
  end

  test do
    flags = shell_output("pkgconf --cflags --libs noqtis").split
    system ENV.cc, "-std=c11", pkgshare/"consumer/use.c", "-o", "usepc",
           *flags
    system "./usepc"
    system "cmake", "-S", pkgshare/"consumer", "-B", "cm",
           "-DCMAKE_PREFIX_PATH=#{prefix}"
    system "cmake", "--build", "cm"
    system "./cm/use"
  end
end
