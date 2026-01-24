#!/bin/bash

# Assumes `ocserv` is already installed
# or i guess TODO

# Parameters? kinda
CERTIFICATE_AUTHORITY=""
ORGANIZATION=""
PORT=""
NETWORK=""
DNS=""

comment_out() {
    sed -i -E "s/^[[:space:]]*#?[[:space:]]*($1[[:space:]]*=.*)$/#\1/" $CONF
}

# check that variables are non empty
if [ -z "$CERTIFICATE_AUTHORITY" -o -z "$ORGANIZATION" -o -z "$PORT" -o -z "$NETWORK" -o -z "$DNS" ]
then
	echo "ERROR: Fill in variables first"
	exit 1
fi

# check if ocserv, iptables, certtool
if ! command -v ocserv || ! command -v iptables || ! command -v certtool; then
    echo "ERROR: ocserv, iptables, and/or certtool is not installed"
    exit 1
fi

CONF="/etc/ocserv/ocserv.conf"
mkdir /root/certificates
cd /root/certificates

# certifications
cat << EOF > ca.tmpl
cn = "$CERTIFICATE_AUTHORITY"
organization = "$ORGANIZATION"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOF

cat << EOF > server.tmpl
cn = "$HOSTNAME"
organization = "$ORGANIZATION"
serial = 2
expiration_days = 3650
signing_key
encryption_key
tls_www_server
dns_name = "$ORGANIZATION"
EOF

certtool --generate-privkey --outfile ca-key.pem
certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile  ca-cert.pem

certtool --generate-privkey --outfile server-key.pem
certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem

cp server-cert.pem server-key.pem /etc/ocserv

# config file

# authorization (chatgpt)
comment_out "auth"
sed -i -E 's/^[[:space:]]*#(auth[[:space:]]*=[[:space:]]*"pam")/\1/' $CONF

# set cert and key files
comment_out "server-cert"
comment_out "server-key"
echo "server-cert = /etc/ocserv/server-cert.pem" >> $CONF
echo "server-key = /etc/ocserv/server-key.pem" >> $CONF

# port
sed -i -e "/^[[:space:]]*tcp-port =/ s/= .*/= $PORT/" $CONF
sed -i -e "/^[[:space:]]*udp-port =/ s/= .*/= $PORT/" $CONF

# subnet
comment_out "ipv4-network"
comment_out "ipv4-netmask"
echo "ipv4-network = $NETWORK/24" >> $CONF

# dns (not sure if necessary)
sed -i -e "/^[[:space:]]*dns =/ s/= .*/= $DNS/" $CONF

# routes (copied from above)
comment_out "route"
echo "route = $NETWORK/24" >> $CONF
echo "route = 192.168.220.0/24" >> $CONF

# start
ocserv -c /etc/ocserv/ocserv.conf

# congfigure forwarding things
sed -i -E "s/^[[:space:]]*#?[[:space:]]*(net\.ipv4\.ip_forward[[:space:]]*=.*)$/#\1/" /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p /etc/sysctl.conf
iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE # sometimes it just doesn't do this?
