# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/ubuntu:18.04 as builder-base

ARG ARCH=amd64
ENV ARCH=${ARCH}

ENV GO_VERSION 1.14.2
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

COPY install-deps.sh /tmp/install-deps.sh
RUN /tmp/install-deps.sh

COPY install-go.sh /tmp/install-go.sh
RUN /tmp/install-go.sh

FROM scratch
COPY --from=builder-base / /
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
