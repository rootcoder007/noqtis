# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# ClusterFuzzLite build image (.github/workflows/cflite.yml): the same
# build as OSS-Fuzz's (fuzz/oss-fuzz/), from the checked-out source
# instead of a clone of main.
FROM gcr.io/oss-fuzz-base/base-builder
COPY . $SRC/noqtis
WORKDIR $SRC/noqtis
COPY fuzz/oss-fuzz/build.sh $SRC/
