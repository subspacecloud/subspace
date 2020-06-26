FROM alpine AS builder

# Download QEMU, see https://github.com/docker/hub-feedback/issues/1261
ENV QEMU_URL https://github.com/balena-io/qemu/releases/download/v3.0.0%2Bresin/qemu-3.0.0+resin-aarch64.tar.gz
RUN apk add curl && curl -L ${QEMU_URL} | tar zxvf - -C . --strip-components 1


FROM i386/golang:1.14.4-buster as build

# Add QEMU
COPY --from=builder qemu-aarch64-static /usr/bin

RUN apt-get update \
    && apt-get install -y git make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Makefile ./
# go.mod and go.sum if exists
COPY go.* ./
COPY *.go ./
COPY static ./static
COPY templates ./templates
COPY email ./email

ARG BUILD_VERSION=unknown
ARG GOARCH=386

ENV GODEBUG="netdns=go http2server=0"

RUN make BUILD_VERSION=${BUILD_VERSION} GOARCH=${GOARCH}

FROM i386/alpine:3.11.6

# Add QEMU
COPY --from=builder qemu-aarch64-static /usr/bin

LABEL maintainer="github.com/subspacecommunity/subspace"

COPY --from=build  /src/subspace-linux-amd64 /usr/bin/subspace
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY bin/my_init /sbin/my_init

ENV DEBIAN_FRONTEND noninteractive

RUN chmod +x /usr/bin/subspace /usr/local/bin/entrypoint.sh /sbin/my_init

RUN apk add --no-cache \
    iproute2 \
    iptables \
    ip6tables \
    dnsmasq \
    socat  \
    wireguard-tools \
    runit

ENTRYPOINT ["/usr/local/bin/entrypoint.sh" ]

CMD [ "/sbin/my_init" ]
