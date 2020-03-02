# Subspace - A simple WireGuard VPN server GUI

![Screenshot](https://raw.githubusercontent.com/subspacecloud/subspace/master/screenshot1.png?cachebust=8923409243)

## Screenshots

[Screenshot 1](https://raw.githubusercontent.com/subspacecloud/subspace/master/screenshot1.png)

[Screenshot 2](https://raw.githubusercontent.com/subspacecloud/subspace/master/screenshot2.png)

[Screenshot 3](https://raw.githubusercontent.com/subspacecloud/subspace/master/screenshot3.png)

[Screenshot 4](https://raw.githubusercontent.com/subspacecloud/subspace/master/screenshot4.png)

## Features

* **WireGuard VPN Protocol**
  * The most modern and fastest VPN protocol.
* **Single Sign-On (SSO) with SAML**
  * Support for SAML providers like G Suite and Okta.
* **Add Devices**
  * Connect from Mac OS X, Windows, Linux, Android, or iOS.
* **Remove Devices**
  * Removes client key and disconnects client.
* **Auto-generated Configs**
  * Each client gets a unique downloadable config file.
  * Generates a QR code for easy importing on iOS and Android.

## Run Subspace on Portal Cloud

Portal Cloud is a hosting service that enables anyone to run open source cloud applications.

[Sign up for Portal Cloud](https://portal.cloud/) and get $15 free credit with code **Portal15**.

## Run Subspace on a VPS

Running Subspace on a VPS is designed to be as simple as possible.

  * Public Docker image.
  * Single static Go binary with assets bundled.
  * Automatic TLS using Let's Encrypt.
  * Redirects http to https.
  * Works with a reverse proxy or standalone.

### 1. Get a server

**Recommended Specs**

* Type: VPS or dedicated
* Distribution: Ubuntu 16.04 (Xenial) or Ubuntu 18.04 (Bionic)
* Memory: 512MB or greater

### 2. Add a DNS record

Create a DNS `A` record in your domain pointing to your server's IP address.

**Example:** `subspace.example.com  A  172.16.1.1`

### 3. Enable Let's Encrypt

Subspace runs a TLS ("SSL") https server on port 443/tcp. It also runs a standard web server on port 80/tcp to redirect clients to the secure server. Port 80/tcp is required for Let's Encrypt verification.

**Requirements**

* Your server must have a publicly resolvable DNS record.
* Your server must be reachable over the internet on ports 80/tcp, 443/tcp and 51820/udp (Default WireGuard port, user changeable).

### Usage

**Example usage:**

```bash
$ subspace --http-host subspace.example.com
```
### Usage

```bash
  -backlink string
        backlink (optional)
  -datadir string
        data dir (default "/data")
  -debug
        debug mode
  -help
        display help and exit
  -http-addr string
        HTTP listen address (default ":80")
  -http-host string
        HTTP host
  -http-insecure
        enable sessions cookies for http (no https) not recommended
  -letsencrypt
        enable TLS using Let's Encrypt on port 443 (default true)
  -version
        display version and exit
```
### Run as a Docker container

#### Install WireGuard on the host

The container expects WireGuard to be installed on the host. The official image is `subspacecloud/subspace`.

```bash
add-apt-repository -y ppa:wireguard/wireguard
apt-get update
apt-get install -y wireguard

# Remove dnsmasq because it will run inside the container.
apt-get remove -y dnsmasq

# Set DNS server.
echo nameserver 1.1.1.1 >/etc/resolv.conf

# Load modules.
modprobe wireguard
modprobe iptable_nat
modprobe ip6table_nat

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

```

Follow the official Docker install instructions: [Get Docker CE for Ubuntu](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/)

Make sure to change the `--env SUBSPACE_HTTP_HOST` to your publicly accessible domain name.

```bash

# Your data directory should be bind-mounted as `/data` inside the container using the `--volume` flag.
$ mkdir /data

docker create \
    --name subspace \
    --restart always \
    --network host \
    --cap-add NET_ADMIN \
    --volume /usr/bin/wg:/usr/bin/wg \
    --volume /data:/data \
    --env SUBSPACE_HTTP_HOST="subspace.example.com" \
	# Optional variable to change upstream DNS provider
    --env SUBSPACE_NAMESERVER="1.1.1.1" \
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
    subspacecloud/subspace:latest

$ sudo docker start subspace

$ sudo docker logs subspace

<log output>

```

#### Docker-Compose Example

```
version: "3.3"
services:
  subspace:
   image: subspace/subspace:latest
   container_name: subspace
   volumes:
    - /usr/bin/wg:/usr/bin/wg
    - /opt/docker/subspace:/data
   restart: always
   environment:
    - SUBSPACE_HTTP_HOST=subspace.example.org
    - SUBSPACE_LETSENCRYPT=true
    - SUBSPACE_HTTP_INSECURE=false
    - SUBSPACE_HTTP_ADDR=":80"
    - SUBSPACE_NAMESERVER=1.1.1.1
    - SUBSPACE_LISTENPORT=51820
   cap_add:
    - NET_ADMIN
   network_mode: "host"
```

#### Updating the container image

Pull the latest image, remove the container, and re-create the container as explained above.

```bash
# Pull the latest image
$ sudo docker pull subspacecloud/subspace

# Stop the container
$ sudo docker stop subspace

# Remove the container (data is stored on the mounted volume)
$ sudo docker rm subspace

# Re-create and start the container
$ sudo docker create ... (see above)
```

## Help / Reporting Bugs

Email support@portal.cloud

