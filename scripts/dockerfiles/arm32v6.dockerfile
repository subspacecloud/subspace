FROM alpine AS builder

# Download QEMU, see https://github.com/docker/hub-feedback/issues/1261
ENV QEMU_URL https://github.com/balena-io/qemu/releases/download/v3.0.0%2Bresin/qemu-3.0.0+resin-arm.tar.gz
RUN apk add curl && curl -L ${QEMU_URL} | tar zxvf - -C . --strip-components 1


FROM arm32v6/golang:1.14.4-alpine as build

# Add QEMU
COPY --from=builder qemu-arm-static /usr/bin

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /src

COPY Makefile ./
# go.mod and go.sum if exists
COPY go.* ./
COPY cmd/ ./cmd
COPY web ./web

ARG BUILD_VERSION=unknown
ARG GOARCH=arm
ENV GOARM=6

ENV GODEBUG="netdns=go http2server=0"

RUN make build BUILD_VERSION=${BUILD_VERSION}


FROM arm32v6/alpine:3.11.6
LABEL maintainer="github.com/subspacecommunity/subspace"

# Add QEMU
COPY --from=builder qemu-arm-static /usr/bin

ENV DEBIAN_FRONTEND noninteractive
RUN apk add --no-cache \
    iproute2 \
    iptables \
    ip6tables \
    dnsmasq \
    socat  \
    wireguard-tools \
    runit

COPY --from=build  /src/subspace /usr/bin/subspace
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY bin/my_init /sbin/my_init

RUN chmod +x /usr/bin/subspace /usr/local/bin/entrypoint.sh /sbin/my_init

ENTRYPOINT ["/usr/local/bin/entrypoint.sh" ]

CMD [ "/sbin/my_init" ]
