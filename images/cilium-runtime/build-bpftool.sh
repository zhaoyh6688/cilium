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

git clone --depth 1 -b master git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git /tmp/linux

cd /tmp/linux/tools/bpf/bpftool
git_log
make -j "$(getconf _NPROCESSORS_ONLN)"
strip bpftool

mkdir -p /out/bin
mv bpftool /out/bin
