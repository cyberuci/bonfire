#!/usr/bin/env python3

import grp
import os
import pwd
import subprocess
import sys

USERS_FILE = "users.conf"

# Check if running as root
if os.geteuid() != 0:
    sys.exit("Error: Must run as root")

def run(cmd):
    subprocess.call(cmd)

def user_exists(u):
    try:
        pwd.getpwnam(u)
        return True
    except KeyError:
        return False

# Parse simple key=value,value format
if not os.path.exists(USERS_FILE):
    sys.exit("Error: %s not found" % USERS_FILE)

users = set()
admins = set()

with open(USERS_FILE) as f:
    for line in f:
        if "=" in line:
            key, value = line.split("=", 1)
            items = set(v.strip() for v in value.split(",") if v.strip())
            if key.strip() == "users":
                users = items
            elif key.strip() == "admins":
                admins = items

if not users:
    sys.exit("Error: No users in %s" % USERS_FILE)

if not admins:
    sys.exit("Error: No admins in %s" % USERS_FILE)

# Admins are implicitly users
users = users | admins

# Remove unauthorized users
system_users = [u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000]
for u in system_users:
    if u not in users:
        print("Removing user: %s" % u)
        run(["userdel", u])

# Add missing users
for u in users:
    if not user_exists(u):
        print("Adding user: %s" % u)
        run(["useradd", u])

# Determine admin groups based on distro
admin_groups = ["adm"]
if os.path.exists("/etc/redhat-release"):
    admin_groups.append("wheel")
else:
    admin_groups.append("sudo")

# Manage admin groups
for group in admin_groups:
    try:
        members = set(grp.getgrnam(group).gr_mem)
    except KeyError:
        continue

    for a in admins:
        if user_exists(a) and a not in members:
            print("Adding %s to %s" % (a, group))
            run(["usermod", "-aG", group, a])

    for u in users:
        if user_exists(u) and u in members and u not in admins:
            print("Removing %s from %s" % (u, group))
            run(["gpasswd", "-d", u, group])

print("Authorized users configured.")