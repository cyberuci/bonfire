#!/bin/sh

if ! command -v rc-service || ! command -v rc-update || ! command -v apk ; then
    echo "This doesn't appear to be Alpine Linux, aborting"
    exit 1
fi

apk add rsyslog utmps util-linux-login
setup-utmp
rc-update del syslog boot
service syslog stop
rc-update add rsyslog boot
service rsyslog start