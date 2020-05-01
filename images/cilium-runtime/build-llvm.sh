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

# This script builds clang and llc with just the BPF backend

git clone --branch master https://github.com/llvm/llvm-project.git /tmp/llvm

cd /tmp/llvm
mkdir -p ./llvm/build/install
git checkout -b build d941df363d1cb621a3836b909c37d79f2a3e27e2 
git_log
cd ./llvm/build
cmake .. -G "Ninja" -DLLVM_TARGETS_TO_BUILD="BPF" -DLLVM_ENABLE_PROJECTS="clang" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DLLVM_BUILD_RUNTIME=OFF
ninja clang llc
strip bin/clang
strip bin/llc

cp bin/clang /usr/bin/clang
cp bin/llc /usr/bin/llc

mkdir -p /out/bin
mv bin/clang /out/bin
mv bin/llc /out/bin
