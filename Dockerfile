FROM phusion/baseimage:0.11
MAINTAINER github.com/soundscapecloud/soundscape

COPY subspace-linux-amd64 /usr/bin/subspace
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENV DEBIAN_FRONTEND noninteractive

RUN chmod +x /usr/bin/subspace /usr/local/bin/entrypoint.sh

RUN apt-get update \
    && apt-get install -y iproute2 iptables dnsmasq socat

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]

CMD [ "/sbin/my_init" ]
