#!/usr/bin/env bash
set -e

OVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_NAME="$(hostname)"

# PROMPT USER FOR CLIENT TO GENERATE KEYS FOR OR USE ENV VARS IF SET
CLIENT_NAME="${CLIENT_NAME:-}"
if [ -z "$CLIENT_NAME" ]; then 
    read -rp "Enter hostname of client: " CLIENT_NAME; 
fi


cd $EASYRSA_DIR 
export EASYRSA_BATCH=1
export EASYRSA_REQ_CN="CLIENT_NAME"

# GENERATE KEYS
if [ ! -f "pki/private/${CLIENT_NAME}.key" ]; then
  ./easyrsa gen-req "$CLIENT_NAME" nopass
fi
if [ ! -f "pki/issued/${CLIENT_NAME}.crt" ]; then
  ./easyrsa sign-req client "$CLIENT_NAME"
fi