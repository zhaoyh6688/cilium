#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

curl --silent --show-error --location "https://dl.google.com/go/go${GO_VERSION}.linux-${ARCH}.tar.gz" --output /tmp/go.tgz
tar -xzf /tmp/go.tgz -C /usr/local

GO111MODULE=on go get github.com/gordonklaus/ineffassign@1003c8bd00dc2869cb5ca5282e6ce33834fed514

go clean -cache -modcache
