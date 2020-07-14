FROM alpine AS builder

# Download QEMU, see https://github.com/docker/hub-feedback/issues/1261
ENV QEMU_URL https://github.com/balena-io/qemu/releases/download/v3.0.0%2Bresin/qemu-3.0.0+resin-arm.tar.gz
RUN apk add curl && curl -L ${QEMU_URL} | tar zxvf - -C . --strip-components 1


FROM arm32v5/golang:1.14.4-buster as build

# Add QEMU
COPY --from=builder qemu-arm-static /usr/bin

RUN apt-get update \
    && apt-get install -y git make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Makefile ./
# go.mod and go.sum if exists
COPY go.* ./
COPY cmd/ ./cmd
COPY web ./web

ARG BUILD_VERSION=unknown
ARG GOARCH=arm
ENV GOARM=5

ENV GODEBUG="netdns=go http2server=0"

RUN make build BUILD_VERSION=${BUILD_VERSION}


FROM arm32v5/debian:buster-backports
LABEL maintainer="github.com/subspacecommunity/subspace"

# Add QEMU
COPY --from=builder qemu-arm-static /usr/bin

RUN apt-get update \
    && apt-get install -y \
    iproute2 \
    iptables \
    dnsmasq \
    socat  \
    wireguard-tools \
    runit \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build  /src/subspace /usr/bin/subspace
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY bin/my_init /sbin/my_init

ENV DEBIAN_FRONTEND noninteractive

RUN chmod +x /usr/bin/subspace /usr/local/bin/entrypoint.sh /sbin/my_init

ENTRYPOINT ["/usr/local/bin/entrypoint.sh" ]

CMD [ "/sbin/my_init" ]
