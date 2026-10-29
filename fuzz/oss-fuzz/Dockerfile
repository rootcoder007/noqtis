# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# OSS-Fuzz build image for noqtis: the library needs only a C11
# compiler, which base-builder has.
FROM gcr.io/oss-fuzz-base/base-builder
RUN git clone --depth 1 https://github.com/rootcoder007/noqtis noqtis
WORKDIR $SRC/noqtis
COPY build.sh $SRC/
