# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# ClusterFuzzLite build image (.github/workflows/cflite.yml): the same
# build as OSS-Fuzz's (fuzz/oss-fuzz/), from the checked-out source
# instead of a clone of main.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760
COPY . $SRC/noqtis
WORKDIR $SRC/noqtis
COPY fuzz/oss-fuzz/build.sh $SRC/
