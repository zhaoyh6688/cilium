# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/ubuntu:18.04 as runtime-base
COPY install-base-deps.sh  /tmp/install-base-deps.sh
RUN /tmp/install-base-deps.sh

FROM runtime-base as runtime-build
ARG ARCH=amd64
ENV ARCH=${ARCH}

# For optimal use of cache each scrip is copied separately,
# which means that when build-iproute2.sh changes, build-llvm.sh
# won't have re-run; also build-llvm.sh is placed first as it
# takes longest to run
COPY install-build-deps.sh /tmp/install-build-deps.sh
RUN /tmp/install-build-deps.sh

COPY build-llvm.sh /tmp/build-llvm.sh
RUN /tmp/build-llvm.sh

COPY build-iproute2.sh /tmp/build-iproute2.sh
RUN /tmp/build-iproute2.sh

COPY build-bpftool.sh /tmp/build-bpftool.sh
RUN /tmp/build-bpftool.sh

COPY download-cni-loopback.sh /tmp/download-cni-loopback.sh
RUN /tmp/download-cni-loopback.sh

FROM docker.io/library/golang:1.14.2 as runtime-gobuild

COPY build-gops.sh /tmp/build-gops.sh
RUN /tmp/build-gops.sh

FROM runtime-base as runtime-base-stripped

COPY cleanup.sh /tmp/cleanup.sh
RUN /tmp/cleanup.sh

COPY --from=runtime-build /out /
COPY --from=runtime-gobuild /out /

FROM runtime-base-stripped
LABEL maintainer="maintainer@cilium.io"
