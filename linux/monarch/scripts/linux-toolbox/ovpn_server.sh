#!/usr/bin/env bash
set -e

OVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_NAME="$(hostname)"


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
echo "[4] creating keys, signing, and dh params"
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
persist-key 
persist-tun 
verb 3 

ca ca.crt 
cert ${SERVER_NAME}.crt 
key ${SERVER_NAME}.key 
dh dh.pem 
tls-auth ta.key 0 

EOF

# enable port forwarding
echo "[9] enabling port forwarding"
sed -i "s/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/" /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

echo "[complete] server configured"