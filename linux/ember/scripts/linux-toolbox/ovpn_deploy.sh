#!/usr/bin/env bash
set -e

OVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_NAME="$(hostname)"
CLIENT_NAME="uclient"

# CHECK DEPENDENCIES
for cmd in openvpn make-cadir iptables ip; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: Required command '$cmd' is not installed."
        exit 1
    fi
done

if [ -z "$SERVER_IP" ]; then
    if [ -t 0 ]; then
        read -rp "Enter VPN Server IP: " SERVER_IP
    else
        echo "Error: SERVER_IP is not set and script is running non-interactively."
        exit 1
    fi
fi

# CREATING EASY-RSA DIRECTORY
if command -v make-cadir &>/dev/null; then
    echo "[1] creating easy-rsa dir"
    if [ ! -d "$EASYRSA_DIR" ]; then
        make-cadir "$EASYRSA_DIR"
    else
        echo "[!] easy-rsa dir already exists"
    fi
else
    echo "[!] make-cadir is not an available command"
fi

# INITIALIZING PKI and CA
cd "$EASYRSA_DIR"
export EASYRSA_BATCH=1

echo "[2] initializing PKI"
if [ ! -d "pki" ]; then
    ./easyrsa init-pki
else
    echo "[!] pki already exists"
fi

echo "[3] building CA"
if [ ! -f "pki/ca.crt" ]; then
    export EASYRSA_REQ_CN="Easy-RSA CA"
    ./easyrsa build-ca nopass
else
    echo "[!] pki/ca.crt already exists"
fi

# CREATE KEYS AND CERT FOR SERVER + DH PARAMS
echo "[4] creating server keys, signing, and dh params"
if [ ! -f "pki/private/$SERVER_NAME.key" ]; then
    export EASYRSA_REQ_CN="$SERVER_NAME"
    ./easyrsa gen-req "$SERVER_NAME" nopass
else
    echo "[!] pki/private/$SERVER_NAME.key already exists"
fi

if [ ! -f "pki/dh.pem" ]; then
    ./easyrsa gen-dh
else
    echo "[!] pki/dh.pem already exists"
fi

if [ ! -f "pki/issued/$SERVER_NAME.crt" ]; then
    export EASYRSA_REQ_CN="$SERVER_NAME"
    ./easyrsa sign-req server "$SERVER_NAME"
else
    echo "[!] pki/issued/$SERVER_NAME.crt already exists"
fi

# GENERATING UNIVERSAL CLIENT KEYS AND CERT
echo "[5] creating client keys and signing"
if [ ! -f "pki/private/$CLIENT_NAME.key" ]; then
    export EASYRSA_REQ_CN="$CLIENT_NAME"
    ./easyrsa gen-req "$CLIENT_NAME" nopass
else
    echo "[!] pki/private/$CLIENT_NAME.key already exists"
fi

if [ ! -f "pki/issued/$CLIENT_NAME.crt" ]; then
    export EASYRSA_REQ_CN="$CLIENT_NAME"
    ./easyrsa sign-req client "$CLIENT_NAME"
else
    echo "[!] pki/issues/$CLIENT_NAME.crt already exists"
fi

# GENERATE TA KEY IF NEEDED
echo "[6] generating TA key"
if [ ! -f "$OVPN_DIR/ta.key" ]; then
    cd $OVPN_DIR && openvpn --genkey secret ta.key
else
    echo "[!] ta key already exists"
fi

# MOVE FILES TO /etc/openvpn
echo "[7] move keys and certs to $OVPN_DIR"
cd $EASYRSA_DIR && cp pki/dh.pem pki/ca.crt pki/issued/$SERVER_NAME.crt pki/private/$SERVER_NAME.key $OVPN_DIR

# CONFIGURING SERVER
echo "[8] configuring $OVPN_DIR$SERVER_NAME.conf"
cat > $OVPN_DIR/$SERVER_NAME.conf << EOF
port 1194 
proto udp 
dev tun 
server 10.8.0.0 255.255.255.0 
ifconfig-pool-persist /var/log/openvpn/ipp.txt 
keepalive 10 120 
cipher AES-256-CBC 
comp-lzo no
persist-key 
persist-tun 
verb 3 

ca ca.crt 
cert ${SERVER_NAME}.crt 
key ${SERVER_NAME}.key 
dh dh.pem 
tls-auth ta.key 0 

duplicate-cn
EOF

# enable port forwarding
echo "[9] enabling port forwarding"
sed -i "s/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/" /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

# enable NAT
echo "[9.5] enabling NAT"
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

echo "[10] generating unified client file $CLIENT_NAME.ovpn"
cat > $OVPN_DIR/$CLIENT_NAME.ovpn << EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
resolv-retry infinite
nobind
key-direction 1
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-256-CBC
comp-lzo no
verb 3
EOF

cd $OVPN_DIR
{
    echo "<ca>"
    cat "$OVPN_DIR/ca.crt"
    echo "</ca>"
    echo "<cert>"
    openssl x509 -in "$EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt"
    echo "</cert>"
    echo "<key>"
    cat "$EASYRSA_DIR/pki/private/$CLIENT_NAME.key"
    echo "</key>"
    echo "<tls-auth>"
    cat "$OVPN_DIR/ta.key"
    echo "</tls-auth>"
} >> "$CLIENT_NAME.ovpn"

echo "[complete] server configured"