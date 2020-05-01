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

go get -d github.com/google/gops
cd /go/src/github.com/google/gops
git checkout -b build v0.3.6
git_log
go install
strip /go/bin/gops

mkdir -p /out/bin
mv /go/bin/gops /out/bin
