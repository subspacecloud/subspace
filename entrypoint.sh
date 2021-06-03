#!/usr/bin/env sh
set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

# Require environment variables.
if [ -z "${SUBSPACE_HTTP_HOST-}" ]; then
  echo "Environment variable SUBSPACE_HTTP_HOST required. Exiting."
  exit 1
fi
# Optional environment variables.
if [ -z "${SUBSPACE_BACKLINK-}" ]; then
  export SUBSPACE_BACKLINK="/"
fi

if [ -z "${SUBSPACE_IPV4_POOL-}" ]; then
  export SUBSPACE_IPV4_POOL="10.99.97.0/24"
fi
if [ -z "${SUBSPACE_IPV6_POOL-}" ]; then
  export SUBSPACE_IPV6_POOL="fd00::10:97:0/112"
fi
if [ -z "${SUBSPACE_NAMESERVERS-}" ]; then
  export SUBSPACE_NAMESERVERS="1.1.1.1,1.0.0.1"
fi

if [ -z "${SUBSPACE_LETSENCRYPT-}" ]; then
  export SUBSPACE_LETSENCRYPT="true"
fi

if [ -z "${SUBSPACE_HTTP_ADDR-}" ]; then
  export SUBSPACE_HTTP_ADDR=":80"
fi

if [ -z "${SUBSPACE_LISTENPORT-}" ]; then
  export SUBSPACE_LISTENPORT="51820"
fi

if [ -z "${SUBSPACE_HTTP_INSECURE-}" ]; then
  export SUBSPACE_HTTP_INSECURE="false"
fi

if [ -z "${SUBSPACE_THEME-}" ]; then
  export SUBSPACE_THEME="green"
fi

export DEBIAN_FRONTEND="noninteractive"

if [ -z "${SUBSPACE_IPV4_GW-}" ]; then
  export SUBSPACE_IPV4_PREF=$(echo ${SUBSPACE_IPV4_POOL-} | cut -d '/' -f1 | sed 's/.0$/./g')
  export SUBSPACE_IPV4_GW=$(echo ${SUBSPACE_IPV4_PREF-}1)

fi

if [ -z "${SUBSPACE_IPV6_GW-}" ]; then
  export SUBSPACE_IPV6_PREF=$(echo ${SUBSPACE_IPV6_POOL-} | cut -d '/' -f1 | sed 's/:0$/:/g')
  export SUBSPACE_IPV6_GW=$(echo ${SUBSPACE_IPV6_PREF-}1)
fi

if [ -z "${SUBSPACE_IPV6_NAT_ENABLED-}" ] || [ "${SUBSPACE_IPV6_NAT_ENABLED}" != "0" ]; then
  export SUBSPACE_IPV6_NAT_ENABLED=1
else
  export SUBSPACE_IPV6_NAT_ENABLED=0
fi

if [ -z "${SUBSPACE_IPV4_NAT_ENABLED-}" ] || [ "${SUBSPACE_IPV4_NAT_ENABLED}" != "0" ]; then
  export SUBSPACE_IPV4_NAT_ENABLED=1
else
  export SUBSPACE_IPV4_NAT_ENABLED=0
fi

# DNS server is disabled if the flag is not ommited and set to anything other than 0.
if ! [ -z "${SUBSPACE_DISABLE_DNS-}" ] && [ "${SUBSPACE_DISABLE_DNS}" != "0" ]; then
  export SUBSPACE_DISABLE_DNS=1
else
  export SUBSPACE_DISABLE_DNS=0
fi

if [ "$SUBSPACE_IPV6_NAT_ENABLED" == "0" ] && [ "$SUBSPACE_IPV4_NAT_ENABLED" == "0" ]; then
  echo "One of envionment variables SUBSPACE_IPV6_NAT_ENABLED, SUBSPACE_IPV4_NAT_ENABLED must be set to 1."
  echo "Got SUBSPACE_IPV6_NAT_ENABLED=$SUBSPACE_IPV6_NAT_ENABLED, SUBSPACE_IPV4_NAT_ENABLED=$SUBSPACE_IPV4_NAT_ENABLED"
  exit 1
fi

# Empty out inherited nameservers
echo "" >/etc/resolv.conf
# Set DNS servers
echo ${SUBSPACE_NAMESERVERS} | tr "," "\n" | while read -r ns; do echo "nameserver ${ns}" >>/etc/resolv.conf; done

if [ -z "${SUBSPACE_DISABLE_MASQUERADE-}" ]; then
  if [[ ${SUBSPACE_IPV4_NAT_ENABLED} -ne 0 ]]; then
    # IPv4
    if ! /sbin/iptables -t nat --check POSTROUTING -s ${SUBSPACE_IPV4_POOL} -j MASQUERADE; then
      /sbin/iptables -t nat --append POSTROUTING -s ${SUBSPACE_IPV4_POOL} -j MASQUERADE
    fi

    if ! /sbin/iptables --check FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT; then
      /sbin/iptables --append FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi

    if ! /sbin/iptables --check FORWARD -s ${SUBSPACE_IPV4_POOL} -j ACCEPT; then
      /sbin/iptables --append FORWARD -s ${SUBSPACE_IPV4_POOL} -j ACCEPT
    fi
  fi

  if [[ ${SUBSPACE_IPV6_NAT_ENABLED} -ne 0 ]]; then
    # IPv6
    if ! /sbin/ip6tables -t nat --check POSTROUTING -s ${SUBSPACE_IPV6_POOL} -j MASQUERADE; then
      /sbin/ip6tables -t nat --append POSTROUTING -s ${SUBSPACE_IPV6_POOL} -j MASQUERADE
    fi

    if ! /sbin/ip6tables --check FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT; then
      /sbin/ip6tables --append FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi

    if ! /sbin/ip6tables --check FORWARD -s ${SUBSPACE_IPV6_POOL} -j ACCEPT; then
      /sbin/ip6tables --append FORWARD -s ${SUBSPACE_IPV6_POOL} -j ACCEPT
    fi
  fi
fi

if [[ ${SUBSPACE_IPV4_NAT_ENABLED} -ne 0 ]]; then
  # ipv4 - DNS Leak Protection
  if ! /sbin/iptables -t nat --check OUTPUT -s ${SUBSPACE_IPV4_POOL} -p udp --dport 53 -j DNAT --to ${SUBSPACE_IPV4_GW}:53; then
    /sbin/iptables -t nat --append OUTPUT -s ${SUBSPACE_IPV4_POOL} -p udp --dport 53 -j DNAT --to ${SUBSPACE_IPV4_GW}:53
  fi

  if ! /sbin/iptables -t nat --check OUTPUT -s ${SUBSPACE_IPV4_POOL} -p tcp --dport 53 -j DNAT --to ${SUBSPACE_IPV4_GW}:53; then
    /sbin/iptables -t nat --append OUTPUT -s ${SUBSPACE_IPV4_POOL} -p tcp --dport 53 -j DNAT --to ${SUBSPACE_IPV4_GW}:53
  fi
fi

if [[ ${SUBSPACE_IPV6_NAT_ENABLED} -ne 0 ]]; then
  # ipv6 - DNS Leak Protection
  if ! /sbin/ip6tables --wait -t nat --check OUTPUT -s ${SUBSPACE_IPV6_POOL} -p udp --dport 53 -j DNAT --to ${SUBSPACE_IPV6_GW}; then
    /sbin/ip6tables --wait -t nat --append OUTPUT -s ${SUBSPACE_IPV6_POOL} -p udp --dport 53 -j DNAT --to ${SUBSPACE_IPV6_GW}
  fi

  if ! /sbin/ip6tables --wait -t nat --check OUTPUT -s ${SUBSPACE_IPV6_POOL} -p tcp --dport 53 -j DNAT --to ${SUBSPACE_IPV6_GW}; then
    /sbin/ip6tables --wait -t nat --append OUTPUT -s ${SUBSPACE_IPV6_POOL} -p tcp --dport 53 -j DNAT --to ${SUBSPACE_IPV6_GW}
  fi
fi
#
# WireGuard (${SUBSPACE_IPV4_POOL})
#
umask_val=$(umask)
umask 0077
if ! test -d /data/wireguard; then
  mkdir /data/wireguard
  cd /data/wireguard

  mkdir clients
  touch clients/null.conf # So you can cat *.conf safely
  mkdir peers
  touch peers/null.conf # So you can cat *.conf safely

  # Generate public/private server keys.
  wg genkey | tee server.private | wg pubkey >server.public
fi

cat <<WGSERVER >/data/wireguard/server.conf
[Interface]
PrivateKey = $(cat /data/wireguard/server.private)
ListenPort = ${SUBSPACE_LISTENPORT}

WGSERVER
cat /data/wireguard/peers/*.conf >>/data/wireguard/server.conf
umask ${umask_val}
[ -f /data/config.json ] && chmod 600 /data/config.json # Special handling of file not created by start-up script

if ip link show wg0 2>/dev/null; then
  ip link del wg0
fi
ip link add wg0 type wireguard
if [[ ${SUBSPACE_IPV4_NAT_ENABLED} -ne 0 ]]; then
  export SUBSPACE_IPV4_CIDR=$(echo ${SUBSPACE_IPV4_POOL-} | cut -d '/' -f2)
  ip addr add ${SUBSPACE_IPV4_GW}/${SUBSPACE_IPV4_CIDR} dev wg0
fi
if [[ ${SUBSPACE_IPV6_NAT_ENABLED} -ne 0 ]]; then
  export SUBSPACE_IPV6_CIDR=$(echo ${SUBSPACE_IPV6_POOL-} | cut -d '/' -f2)
  ip addr add ${SUBSPACE_IPV6_GW}/${SUBSPACE_IPV6_CIDR} dev wg0
fi
wg setconf wg0 /data/wireguard/server.conf
ip link set wg0 up

# dnsmasq service
if [[ ${SUBSPACE_DISABLE_DNS} == "0" ]]; then
  DNSMASQ_LISTEN_ADDRESS="127.0.0.1"
  if [[ ${SUBSPACE_IPV4_NAT_ENABLED} -ne 0 ]]; then
    DNSMASQ_LISTEN_ADDRESS="${DNSMASQ_LISTEN_ADDRESS},${SUBSPACE_IPV4_GW}"
  fi
  if [[ ${SUBSPACE_IPV6_NAT_ENABLED} -ne 0 ]]; then
    DNSMASQ_LISTEN_ADDRESS="${DNSMASQ_LISTEN_ADDRESS},${SUBSPACE_IPV6_GW}"
  fi

  if ! test -d /etc/service/dnsmasq; then
    cat <<DNSMASQ >/etc/dnsmasq.conf
    # Only listen on necessary addresses.
    listen-address=${DNSMASQ_LISTEN_ADDRESS}

    # Never forward plain names (without a dot or domain part)
    domain-needed

    # Never forward addresses in the non-routed address spaces.
    bogus-priv
DNSMASQ

    mkdir -p /etc/service/dnsmasq
    cat <<RUNIT >/etc/service/dnsmasq/run
#!/bin/sh
exec /usr/sbin/dnsmasq --no-daemon
RUNIT
    chmod +x /etc/service/dnsmasq/run

    # dnsmasq service log
    mkdir -p /etc/service/dnsmasq/log/main
    cat <<RUNIT >/etc/service/dnsmasq/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
    chmod +x /etc/service/dnsmasq/log/run
  fi
fi

# subspace service
if ! test -d /etc/service/subspace; then
  mkdir /etc/service/subspace
  cat <<RUNIT >/etc/service/subspace/run
#!/bin/sh
source /etc/envvars
exec /usr/bin/subspace \
    "--http-host=${SUBSPACE_HTTP_HOST}" \
    "--http-addr=${SUBSPACE_HTTP_ADDR}" \
    "--http-insecure=${SUBSPACE_HTTP_INSECURE}" \
    "--backlink=${SUBSPACE_BACKLINK}" \
    "--letsencrypt=${SUBSPACE_LETSENCRYPT}" \
    "--theme=${SUBSPACE_THEME}"
RUNIT
  chmod +x /etc/service/subspace/run

  # subspace service log
  mkdir /etc/service/subspace/log
  mkdir /etc/service/subspace/log/main
  cat <<RUNIT >/etc/service/subspace/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
  chmod +x /etc/service/subspace/log/run
fi

exec $@
