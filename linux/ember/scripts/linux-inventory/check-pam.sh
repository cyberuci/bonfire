#!/bin/sh

if [ -e /lib/x86_64-linux-gnu/security/pam_deny.so ]; then
    strings /lib/x86_64-linux-gnu/security/pam_deny.so
fi

if [ -e /usr/lib/security/pam_deny.so ]; then
    strings /usr/lib/security/pam_deny.so
fi

if [ -e /usr/lib64/security/pam_deny.so ]; then
    strings /usr/lib64/security/pam_deny.so
fi
