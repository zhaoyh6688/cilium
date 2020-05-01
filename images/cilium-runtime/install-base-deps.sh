#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# Install prepackaged Cilium runtime base dependencies

packages=(
  bash-completion
  ca-certificates
  iptables
  kmod
)

# Additional iproute2 runtime dependencies
packages+=(
  libelf1
  libmnl0
)

# Additional BPF build runtime dependencies
packages+=(
  libgcc-5-dev
)

apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends "${packages[@]}"
