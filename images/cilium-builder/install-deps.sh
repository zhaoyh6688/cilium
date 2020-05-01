#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

packages=(
  apt-utils
  binutils
  ca-certificates
  clang-7
  coreutils
  curl
  gcc
  git
  iproute2
  libc6-dev
  libelf-dev
  llvm-7
  m4
  make
  pkg-config
  python
  rsync
  unzip
  wget
  xz-utils
  zip
  zlib1g-dev
)

apt-get update
apt-get upgrade -y

apt-get install -y --no-install-recommends "${packages[@]}"

update-alternatives --install /usr/bin/clang clang /usr/bin/clang-7 100
update-alternatives --install /usr/bin/llc llc /usr/bin/llc-7 100

apt-get purge -y --auto-remove
apt-get clean

rm -rf /var/lib/apt/lists/*
rm -rf /tmp/* /var/tmp/*
