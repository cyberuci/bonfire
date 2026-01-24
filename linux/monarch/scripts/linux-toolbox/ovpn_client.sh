#!/usr/bin/env bash
set -e

OVPN_DIR="/etc/openvpn"
CLIENT_NAME="$(hostname)"

SERVER_IP="${SERVER_IP:-}"
if [ -z "$SERVER_IP" ]; then
  read -rp "Enter VPN server IP Address: " SERVER_IP
fi

# CONFIGURING SERVER
echo "[1] configuring client.conf"
cat > $OVPN_DIR/client.conf << EOF
port 1194 
proto udp 
dev tun 
persist-key 
persist-tun 
cipher AES-256-CBC
resolv-retry infinite
nobind
remote-cert-tls server
verb 3 

client
ca ca.crt
cert $CLIENT_NAME.crt
key $CLIENT_NAME.key
tls-auth ta.key 1

remote $SERVER_IP 1194

EOF

echo "[complete] client configured"
