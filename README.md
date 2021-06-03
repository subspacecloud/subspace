# Subspace - A simple WireGuard VPN server GUI

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-22-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

[![](https://images.microbadger.com/badges/image/subspacecommunity/subspace.svg)](https://microbadger.com/images/subspacecommunity/subspace "Get your own image badge on microbadger.com") [![](https://images.microbadger.com/badges/version/subspacecommunity/subspace.svg)](https://microbadger.com/images/subspacecommunity/subspace "Get your own version badge on microbadger.com")

[![Go Report Card](https://goreportcard.com/badge/github.com/subspacecommunity/subspace)](https://goreportcard.com/report/github.com/subspacecommunity/subspace)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=subspacecommunity_subspace&metric=alert_status)](https://sonarcloud.io/dashboard?id=subspacecommunity_subspace)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=subspacecommunity_subspace&metric=ncloc)](https://sonarcloud.io/dashboard?id=subspacecommunity_subspace)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=subspacecommunity_subspace&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=subspacecommunity_subspace)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=subspacecommunity_subspace&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=subspacecommunity_subspace)

- [Subspace - A simple WireGuard VPN server GUI](#subspace---a-simple-wireguard-vpn-server-gui)
  - [Slack](#slack)
  - [Screenshots](#screenshots)
  - [Features](#features)
  - [Contributing](#contributing)
  - [Setup](#setup)
    - [1. Get a server](#1-get-a-server)
    - [2. Add a DNS record](#2-add-a-dns-record)
    - [3. Enable Let's Encrypt](#3-enable-lets-encrypt)
    - [Usage](#usage)
      - [Command Line Options](#command-line-options)
    - [Run as a Docker container](#run-as-a-docker-container)
      - [Install WireGuard on the host](#install-wireguard-on-the-host)
      - [Docker-Compose Example](#docker-compose-example)
      - [Updating the container image](#updating-the-container-image)
  - [Contributors ✨](#contributors-)

## Slack

Join the slack community over at the [gophers](https://invite.slack.golangbridge.org/) workspace. Our Channel is `#subspace` which can be used to ask general questions in regards to subspace where the community can assist where possible.

## Screenshots


|                                                                                                      |                                                                                                      |     |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | --- |
| ![Screenshot 1](https://raw.githubusercontent.com/subspacecommunity/subspace/master/.github/screenshot1.png) | ![Screenshot 3](https://raw.githubusercontent.com/subspacecommunity/subspace/master/.github/screenshot3.png) |
| ![Screenshot 2](https://raw.githubusercontent.com/subspacecommunity/subspace/master/.github/screenshot2.png) | ![Screenshot 4](https://raw.githubusercontent.com/subspacecommunity/subspace/master/.github/screenshot4.png) |

## Features

- **WireGuard VPN Protocol**
  - The most modern and fastest VPN protocol.
- **Single Sign-On (SSO) with SAML**
  - Support for SAML providers like G Suite and Okta.
- **Add Devices**
  - Connect from Mac OS X, Windows, Linux, Android, or iOS.
- **Remove Devices**
  - Removes client key and disconnects client.
- **Auto-generated Configs**
  - Each client gets a unique downloadable config file.
  - Generates a QR code for easy importing on iOS and Android.

## Contributing

See the [CONTRIBUTING](https://raw.githubusercontent.com/subspacecommunity/subspace/master/.github/CONTRIBUTING.md) page for additional info.

## Setup

### 1. Get a server

**Recommended Specs**

- Type: VPS or dedicated
- Distribution: Ubuntu 16.04 (Xenial), 18.04 (Bionic) or 20.04 (Focal)
- Memory: 512MB or greater

### 2. Add a DNS record

Create a DNS `A` record in your domain pointing to your server's IP address.

**Example:** `subspace.example.com A 172.16.1.1`

### 3. Enable Let's Encrypt

Subspace runs a TLS ("SSL") https server on port 443/tcp. It also runs a standard web server on port 80/tcp to redirect clients to the secure server. Port 80/tcp is required for Let's Encrypt verification.

**Requirements**

- Your server must have a publicly resolvable DNS record.
- Your server must be reachable over the internet on ports 80/tcp, 443/tcp and 51820/udp (Default WireGuard port, user changeable).

### Usage

**Example usage:**

```bash
$ subspace --http-host subspace.example.com
```

#### Command Line Options

|      flag       | default | description                                                                                                               |
| :-------------: | :-----: | :------------------------------------------------------------------------------------------------------------------------ |
|   `http-host`   |         | REQUIRED: The host to listen on and set cookies for                                                                       |
|   `backlink`    |   `/`   | OPTIONAL: The page to set the home button to                                                                              |
|    `datadir`    | `/data` | OPTIONAL: The directory to store data such as the wireguard configuration files                                           |
|     `debug`     |         | OPTIONAL: Place subspace into debug mode for verbose log output                                                           |
|   `http-addr`   |  `:80`  | OPTIONAL: HTTP listen address                                                                                             |
| `http-insecure` |         | OPTIONAL: enable session cookies for http and remove redirect to https                                                    |
|  `letsencrypt`  | `true`  | OPTIONAL: Whether or not to use a letsencrypt certificate                                                                 |
|     `theme`     | `green` | OPTIONAL: The theme to use, please refer to [semantic-ui](https://semantic-ui.com/usage/theming.html) for accepted colors |
|    `version`    |         | Display version of `subspace` and exit                                                                                    |
|     `help`      |         | Display help and exit                                                                                                     |


### Run as a Docker container

#### Install WireGuard on the host

The container expects WireGuard to be installed on the host. The official image is `subspacecommunity/subspace`.

```bash
apt-get update
apt-get install -y wireguard

# Remove dnsmasq because it will run inside the container.
apt-get remove -y dnsmasq

# Disable systemd-resolved listener if it blocks port 53.
echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
systemctl restart systemd-resolved

# Set Cloudfare DNS server.
echo nameserver 1.1.1.1 > /etc/resolv.conf
echo nameserver 1.0.0.1 >> /etc/resolv.conf

# Load modules.
modprobe wireguard
modprobe iptable_nat
modprobe ip6table_nat

# Enable modules when rebooting.
echo "wireguard" > /etc/modules-load.d/wireguard.conf
echo "iptable_nat" > /etc/modules-load.d/iptable_nat.conf
echo "ip6table_nat" > /etc/modules-load.d/ip6table_nat.conf

# Check if systemd-modules-load service is active.
systemctl status systemd-modules-load.service

# Enable IP forwarding.
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

```

Follow the official Docker install instructions: [Get Docker CE for Ubuntu](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/)

Make sure to change the `--env SUBSPACE_HTTP_HOST` to your publicly accessible domain name.

If you want to run the vpn on a different domain as the http host you can set `--env SUBSPACE_ENDPOINT_HOST`

Use `--env SUBSPACE_DISABLE_DNS=1` to make subspace generate wireguard configs without the `DNS` option, preserving the user's DNS servers.

```bash

# Your data directory should be bind-mounted as `/data` inside the container using the `--volume` flag.
$ mkdir /data

docker create \
    --name subspace \
    --restart always \
    --network host \
    --cap-add NET_ADMIN \
    --volume /data:/data \
    --env SUBSPACE_HTTP_HOST="subspace.example.com" \
	# Optional variable to change upstream DNS provider
    --env SUBSPACE_NAMESERVERS="1.1.1.1,8.8.8.8" \
	# Optional variable to change WireGuard Listenport
    --env SUBSPACE_LISTENPORT="51820" \
  # Optional variables to change IPv4/v6 prefixes
    --env SUBSPACE_IPV4_POOL="10.99.97.0/24" \
    --env SUBSPACE_IPV6_POOL="fd00::10:97:0/64" \
	# Optional variables to change IPv4/v6 Gateway
    --env SUBSPACE_IPV4_GW="10.99.97.1" \
    --env SUBSPACE_IPV6_GW="fd00::10:97:1" \
	# Optional variable to enable or disable IPv6 NAT
    --env SUBSPACE_IPV6_NAT_ENABLED=1 \
  # Optional variable to disable DNS server. Enabled by default.
  # consider disabling DNS server, if supporting international VPN clients
    --env SUBSPACE_DISABLE_DNS=0 \
    subspacecommunity/subspace:latest

$ sudo docker start subspace

$ sudo docker logs subspace

<log output>

```

#### Docker-Compose Example

```
version: "3.3"
services:
  subspace:
   image: subspacecommunity/subspace:latest
   container_name: subspace
   volumes:
    - /opt/docker/subspace:/data
   restart: always
   environment:
    - SUBSPACE_HTTP_HOST=subspace.example.org
    - SUBSPACE_LETSENCRYPT=true
    - SUBSPACE_HTTP_INSECURE=false
    - SUBSPACE_HTTP_ADDR=":80"
    - SUBSPACE_NAMESERVERS=1.1.1.1,8.8.8.8
    - SUBSPACE_LISTENPORT=51820
    - SUBSPACE_IPV4_POOL=10.99.97.0/24
    - SUBSPACE_IPV6_POOL=fd00::10:97:0/64
    - SUBSPACE_IPV4_GW=10.99.97.1
    - SUBSPACE_IPV6_GW=fd00::10:97:1
    - SUBSPACE_IPV6_NAT_ENABLED=1
    - SUBSPACE_DISABLE_DNS=0
   cap_add:
    - NET_ADMIN
   network_mode: "host"
```

#### Updating the container image

Pull the latest image, remove the container, and re-create the container as explained above.

```bash
# Pull the latest image
$ sudo docker pull subspacecommunity/subspace

# Stop the container
$ sudo docker stop subspace

# Remove the container (data is stored on the mounted volume)
$ sudo docker rm subspace

# Re-create and start the container
$ sudo docker create ... (see above)
```

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://duncan.codes"><img src="https://avatars2.githubusercontent.com/u/15332?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Duncan Mac-Vicar P.</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=dmacvicar" title="Code">💻</a></td>
    <td align="center"><a href="https://opsnotice.xyz"><img src="https://avatars1.githubusercontent.com/u/12403145?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Valentin Ouvrard</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=valentin2105" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/agonbar"><img src="https://avatars3.githubusercontent.com/u/1553211?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Adrián González Barbosa</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=agonbar" title="Code">💻</a></td>
    <td align="center"><a href="http://www.improbable.io"><img src="https://avatars3.githubusercontent.com/u/1226100?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Gavin</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=gavinelder" title="Code">💻</a></td>
    <td align="center"><a href="https://squat.ai"><img src="https://avatars1.githubusercontent.com/u/20484159?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Lucas Servén Marín</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=squat" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/jack1902"><img src="https://avatars2.githubusercontent.com/u/39212456?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Jack</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=jack1902" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/ssiuhk"><img src="https://avatars3.githubusercontent.com/u/23556929?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Sam SIU</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=ssiuhk" title="Code">💻</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/wizardels"><img src="https://avatars0.githubusercontent.com/u/17042376?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Elliot Westlake</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=wizardels" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/clementperon"><img src="https://avatars.githubusercontent.com/u/1859302?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Clément Péron</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=clementperon" title="Documentation">📖</a></td>
    <td align="center"><a href="http://blog.selvakn.in"><img src="https://avatars.githubusercontent.com/u/30524?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Selva</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=selvakn" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/syphernl"><img src="https://avatars.githubusercontent.com/u/639906?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Frank</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=syphernl" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/gianlazz"><img src="https://avatars.githubusercontent.com/u/1166579?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Gian Lazzarini</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=gianlazz" title="Documentation">📖</a></td>
    <td align="center"><a href="https://nhamlh.space"><img src="https://avatars.githubusercontent.com/u/11173217?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Nham Le</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=nhamlh" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/sinanmohd"><img src="https://avatars.githubusercontent.com/u/69694713?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Sinan Mohd</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=sinanmohd" title="Documentation">📖</a></td>
  </tr>
  <tr>
    <td align="center"><a href="http://www.sigginet.info"><img src="https://avatars.githubusercontent.com/u/1608474?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Sigurður Guðbrandsson</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=SGudbrandsson" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/vojta7"><img src="https://avatars.githubusercontent.com/u/10436347?v=4?s=100" width="100px;" alt=""/><br /><sub><b>vojta7</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=vojta7" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/d3473r"><img src="https://avatars.githubusercontent.com/u/10356892?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Fabian</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=d3473r" title="Documentation">📖</a></td>
    <td align="center"><a href="http://miki725.com"><img src="https://avatars.githubusercontent.com/u/932940?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Miroslav Shubernetskiy</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=miki725" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/dovreshef"><img src="https://avatars.githubusercontent.com/u/5120549?v=4?s=100" width="100px;" alt=""/><br /><sub><b>dovreshef</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=dovreshef" title="Code">💻</a></td>
    <td align="center"><a href="https://freek.ws/"><img src="https://avatars.githubusercontent.com/u/1370857?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Freekers</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=Freekers" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/Coffeeri"><img src="https://avatars.githubusercontent.com/u/8344540?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Leander</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=Coffeeri" title="Documentation">📖</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/gchamon"><img src="https://avatars.githubusercontent.com/u/9471861?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Gabriel Chamon Araujo</b></sub></a><br /><a href="https://github.com/subspacecommunity/subspace/commits?author=gchamon" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
