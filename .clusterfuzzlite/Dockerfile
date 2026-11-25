# SPDX-License-Identifier: LGPL-3.0-or-later
# ClusterFuzzLite build image (.github/workflows/cflite.yml): the same
# build as OSS-Fuzz's (fuzz/oss-fuzz/), from the checked-out source
# instead of a clone of main.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:ed4aefea5aa72bb8c133576dd13a1417e0fc6eeb27cc0fc7f9880e7e13293b07
COPY . $SRC/noqtis
WORKDIR $SRC/noqtis
COPY fuzz/oss-fuzz/build.sh $SRC/
