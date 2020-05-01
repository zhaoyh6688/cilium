#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

git_log() {
  git --no-pager remote -v
  git --no-pager log -1
}

git clone --depth 1 --branch static-data https://github.com/cilium/iproute2.git /tmp/iproute2

cd /tmp/iproute2
git_log
./configure
make -j "$(getconf _NPROCESSORS_ONLN)"
strip tc/tc
strip ip/ip

mkdir -p /out/bin
mv tc/tc ip/ip /out/bin
