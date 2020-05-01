#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# Install prepackaged Cilium runtime build dependencies

packages=(
  binutils
  ca-certificates
  curl
  make
  xz-utils
)

# Additional iproute2 build dependencies
packages+=(
  bison
  build-essential
  flex
  gcc
  git
  libelf-dev
  libmnl-dev
  pkg-config
)

# Additional bpftool build dependencies
packages+=(
  python3
)

# Additional clang/llvm build dependencies
packages+=(
  cmake
  ninja-build
)

apt-get update
apt-get upgrade -y

apt-get install -y --no-install-recommends "${packages[@]}"
