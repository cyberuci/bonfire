#!/usr/bin/env bash
set -euo pipefail

# Fill in these parameters before running, assume script is running on server

# server parameters (required to run, defaulted values below)
SERVER_ADDRESS="10.8.0.1/24"
SERVER_LISTENPORT="51820"

# client parameters (required to run, defaulted values below)
CLIENT_ADDRESS="10.8.0.2/24"
CLIENT_ALLOWED_IPS="10.8.0.0/24"
SERVER_ENDPOINT="10.8.0.1:51820" #server address + port 51820

# config paths
WG_DIR="/etc/wireguard"
SERVER_CONF="${WG_DIR}/wg0server.conf"
CLIENT_CONF="${WG_DIR}/wg0client.conf"

# key path for server 
SERVER_PRIVKEY_FILE="${WG_DIR}/server_privkey.key"
SERVER_PUBKEY_FILE="${WG_DIR}/server_pubkey.key"

# placeholders for the client keys
CLIENT_PRIVKEY_PLACEHOLDER="insert private key"
CLIENT_PUBKEY_PLACEHOLDER="insert client key"

# will kill script if parameters are empty
die() { echo "ERROR: $*" >&2; exit 1;}

# make sure running as root bc of sysctl
[[ $EUID -eq 0 ]] || die "Run as root"

require_nonempty() {
  local name="$1" val="$2"
  [[ -n "$val" ]] || die "Fill in the required variable: ${name}"
}

# need wireguard installed
require_wireguard() {
  command -v "$1" >/dev/null 2>&1 || die "Need wireguard installed: $1"
}

# validating that the parameters are filled out
require_nonempty "SERVER_ADDRESS" "$SERVER_ADDRESS"
require_nonempty "SERVER_LISTENPORT" "$SERVER_LISTENPORT"
require_nonempty "CLIENT_ADDRESS" "$CLIENT_ADDRESS"
require_nonempty "CLIENT_ALLOWED_IPS" "$CLIENT_ALLOWED_IPS"
require_nonempty "SERVER_ENDPOINT" "$SERVER_ENDPOINT"

# validating that wireguard is installed
require_wireguard wg

# if this machine a iptables, keep the MASQUERADE lines in the conf
HAS_IPTABLES="no"
if command -v iptables >/dev/null 2>&1; then
  HAS_IPTABLES="yes"
else
  echo "iptables isn't installed, the server config file will comment the MASQUERADE line out"
fi

# enable persistent ipv4 forwarding
IPF_CONF="/etc/sysctl.d/99-wireguard-ipforward.conf"
if command -v sysctl >/dev/null 2>&1; then
  echo "net.ipv4.ip_forward = 1" > "$IPF_CONF"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl --system >/dev/null 2>&1 || true
else
  echo "sysctl wasn't found so cannot enable net.ipv4.ip_forward automatically, enable it manually"
fi

# prepping directory
umask 077
mkdir -p "$WG_DIR"

# generate private and public keys if missing
if [[ ! -f "$SERVER_PRIVKEY_FILE" ]]; then
  wg genkey > "$SERVER_PRIVKEY_FILE"
fi
wg pubkey < "$SERVER_PRIVKEY_FILE" > "$SERVER_PUBKEY_FILE"


SERVER_PRIVKEY="$(cat "$SERVER_PRIVKEY_FILE")"
SERVER_PUBKEY="$(cat "$SERVER_PUBKEY_FILE")"

POSTUP_MASQ='PostUp = iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE'
POSTDOWN_MASQ='PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE'

# writing the server config 
{
  echo "[Interface]"
  echo "Address = ${SERVER_ADDRESS}"
  echo "ListenPort = ${SERVER_LISTENPORT}"
  echo "PrivateKey = ${SERVER_PRIVKEY}"
  
  if [[ "$HAS_IPTABLES" == "yes" ]]; then
    echo "${POSTUP_MASQ}"
    echo "${POSTDOWN_MASQ}"
  else
    echo "# ${POSTUP_MASQ}"
    echo "# ${POSTDOWN_MASQ}"
  fi

  echo
  echo "[Peer]"
  echo "# Client 1"
  echo "PublicKey = ${CLIENT_PUBKEY_PLACEHOLDER}"
  echo "AllowedIPs = ${CLIENT_ADDRESS}"
  echo
} > "$SERVER_CONF"

# writing the client config
{
  echo "[Interface]"
  echo "Address = ${CLIENT_ADDRESS}"
  echo "PrivateKey = ${CLIENT_PRIVKEY_PLACEHOLDER}"
  echo
  echo "[Peer]"
  echo "# Server"
  echo "PublicKey = ${SERVER_PUBKEY}"
  echo "Endpoint = ${SERVER_ENDPOINT}"
  echo "AllowedIPs = ${CLIENT_ALLOWED_IPS}"
  echo "PersistentKeepalive = 25"
  echo
} > "$CLIENT_CONF"

# generated ending message
echo "Generated:"
echo "  Server config: $SERVER_CONF"
echo "  Client config: $CLIENT_CONF"
echo "Key files:"
echo "  $SERVER_PRIVKEY_FILE  $SERVER_PUBKEY_FILE"
echo "to generate keys on the client: wg genkey | tee client_privkey.key | wg pubkey > client_pubkey.key"
echo "fill in the client priv and pubkey once generated"
