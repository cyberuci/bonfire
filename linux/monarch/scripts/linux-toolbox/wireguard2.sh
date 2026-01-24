#!/bin/sh
set -euo pipefail

# parameters - set before usage!
LOCAL_SUBNET="" # ex. 192.168.220.0/24
PUBLIC_IP="" # ex. 10.100.21.42

if [ -z "$LOCAL_SUBNET" ] || [ -z "$PUBLIC_IP" ]; then
    echo "Not all parameters set! exiting"
    exit 1
fi

if ! command -v wg || ! command -v wg-quick || ! command -v iptables; then
    echo "ERROR: wg, wg-quick, and/or iptables is not installed"
    exit 1
fi

# xargs to trim whitespace
# NOTE: this probably doesn't work on router so don't do this on there
IFACE=$(ip route get 1.1.1.1 | awk -F'dev ' '{print $2}' | awk '{print $1}' | xargs)
if [ -z "$IFACE" ]; then
    echo "Could not find default interface of machine; exiting"
    exit 1
fi

# xargs to trim whitespace
LOCAL_SUBNET=$(ip addr show dev "$IFACE" | awk -F'inet ' '{print $2}' | awk '{print $1}' | xargs)
if [ -z "$LOCAL_SUBNET" ]; then
    echo "Could not find local subnet of machine; exiting"
    exit 1
fi

# other config
CIDR="/24"

SERVER_ADDRESS="10.9.0.1$CIDR"
SERVER_LISTENPORT="51820"

CLIENT_ADDRESS="10.9.0.2$CIDR"
CLIENT_ALLOWED_IPS="10.9.0.0$CIDR, $LOCAL_SUBNET"
SERVER_ENDPOINT="$PUBLIC_IP:51820"

SERVER_PRIVKEY=$(wg genkey)
SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)

CLIENT_PRIVKEY=$(wg genkey)
CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)

mkdir -p /etc/wireguard
# write server config
cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = $SERVER_ADDRESS
ListenPort = $SERVER_LISTENPORT
PrivateKey = $SERVER_PRIVKEY
PostUp = iptables -t nat -I POSTROUTING -o "$IFACE" -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBKEY
AllowedIPs = $CLIENT_ADDRESS
EOF

cat << EOF > wg0-client.conf
[Interface]
Address = $CLIENT_ADDRESS
PrivateKey = $CLIENT_PRIVKEY

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = $CLIENT_ALLOWED_IPS
EOF
