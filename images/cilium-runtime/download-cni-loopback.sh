#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

curl --silent --show-error --location "https://github.com/containernetworking/plugins/releases/download/v0.7.5/cni-plugins-${ARCH}-v0.7.5.tgz" --output /tmp/cni.tar.gz

cd /tmp
tar -xf cni.tar.gz ./loopback
strip -s loopback

mkdir -p /out/cni
mv loopback /out/cni
