#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The CMAKE_CROSSCOMPILING_EMULATOR of the iOS job: runs a test program
# on the booted simulator with xcrun simctl spawn and exits with its
# status.
#   sim.sh <program> [args...]
# The simulator sees the host's files, so paths need no mapping, but
# spawn starts the program in /; the tests' main shim (tests/cwd.c)
# moves to $NQCWD, here the directory ctest runs the test in. simctl
# passes SIMCTL_CHILD_<name> to the program as <name>, so NQ* variables
# and TMPDIR go across that way.
set -eu
SIMCTL_CHILD_NQCWD=$(pwd)
export SIMCTL_CHILD_NQCWD
SIMCTL_CHILD_TMPDIR=${TMPDIR:-/tmp}
export SIMCTL_CHILD_TMPDIR
for v in $(env | sed -n 's/^\(NQ[A-Z0-9_]*\)=.*/\1/p'); do
  eval "export SIMCTL_CHILD_$v=\"\${$v}\""
done
exec xcrun simctl spawn "${NQSIM:-booted}" "$@"
