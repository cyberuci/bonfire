#!/bin/sh

HOSTNAME=$(hostname || cat /etc/hostname)
echo "HOST: $HOSTNAME"
echo "------------------"

if [ "$#" -lt 1 ]; then
    if [ -n "$AAA" ]; then
        backup_dir="$AAA"
    else
        echo "Usage: $0 <backup_path>"
        echo "Alternatively, set environment variable AAA."
        exit 1
    fi
else
    backup_dir="$1"
fi

if [ -n "$2" ]; then 
    quiet=true
elif [ -n "$BBB" ]; then
    quiet=true
else
    quiet=false
fi

echo_if_not_quiet () {
    if [ "$quiet" = false ]; then
        echo "$1"
    fi
}


sep () {
    echo_if_not_quiet "======================================================================================================="
}

dash_sep () {
    echo_if_not_quiet "-------------------------------------------------------------------------------------------------------"
}


echo_if_not_quiet "Commencing General Backup"
sep
# Ensure the backup directory exists
mkdir -p "$backup_dir" && echo_if_not_quiet "Backup directory created at $backup_dir"
chattr -R -i "$backup_dir"
chmod 600 "$backup_dir"
sep

echo_if_not_quiet "Log Backups"
# Backup logs
log_backup_dir="$backup_dir/logs"
mkdir -p "$log_backup_dir" && echo_if_not_quiet "Log backup directory created at $log_backup_dir"
dash_sep
olddir="$(pwd)"
if cd /var/log; then
  find . -size -1000000k -type f | while read -r file; do
    echo "$file"
    dirname=$(dirname "$file")
    mkdir -p "$log_backup_dir/$dirname"
    cp "$file" "$log_backup_dir/$dirname"
  done
fi
cd "$olddir"

echo_if_not_quiet "Default Firewall Backups"
dash_sep
firewall_backup_dir=$backup_dir/firewall_rules
mkdir -p "$firewall_backup_dir" && echo_if_not_quiet "Firewall backup directory created at $firewall_backup_dir"
chmod 600 "$firewall_backup_dir"
# Backup iptables rules
if command -v iptables-save >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up iptables rules..."
    iptables-save > "$firewall_backup_dir/iptables_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/iptables_rules.bak"
        echo_if_not_quiet "Done backing up iptables rules."
    else
        echo "[!] Error: Failed to create backup for iptables rules."
    fi
else
    echo_if_not_quiet "[-] iptables-save command not found. Skipping iptables backup."
fi

# Backup ufw rules
if command -v ufw >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up ufw rules..."
    ufw status numbered > "$firewall_backup_dir/ufw_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/ufw_rules.bak"
        echo_if_not_quiet "Done backing up ufw rules."
    else
        echo "[!] Error: Failed to create backup for ufw rules."
    fi
else
    echo_if_not_quiet "[-] ufw command not found. Skipping ufw backup."
fi

# Backup nftables rules
if command -v nft >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up nftables rules..."
    nft list ruleset > "$firewall_backup_dir/nftables_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/nftables_rules.bak"
        echo_if_not_quiet "Done backing up nftables rules."
    else
        echo "[!] Error: Failed to create backup for nftables rules."
    fi
else
    echo_if_not_quiet "[-] nft command not found. Skipping nftables backup."
fi

# Backup firewalld rules
if command -v firewall-cmd >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up firewalld rules..."
    firewall-cmd --list-all > "$firewall_backup_dir/firewalld_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/firewalld_rules.bak"
        echo_if_not_quiet "Done backing up firewalld rules."
    else
        echo "[!] Error: Failed to create backup for firewalld rules."
    fi
else
    echo_if_not_quiet "[-] firewall-cmd command not found. Skipping firewalld backup."
fi


# Backup entire /etc directory
echo_if_not_quiet "Backing up /etc..."
tar -czf "$backup_dir/etc.tar.gz" -C / etc 2>/dev/null
if [ $? -eq 0 ]; then
    chmod 600 "$backup_dir/etc.tar.gz"
    echo_if_not_quiet "Done backing up /etc."
else
    echo "[!] Error: Failed to create backup for /etc (some files may have been inaccessible)."
fi
sep

# Backup shell dotfiles for current user (these live outside /etc)
echo_if_not_quiet "Backing up user shell dotfiles..."
for dotfile in .profile .bashrc .bash_aliases .bash_logout .zshrc .zprofile; do
    if [ -f "$HOME/$dotfile" ]; then
        cp "$HOME/$dotfile" "$backup_dir/${dotfile}.bak"
        chmod 600 "$backup_dir/${dotfile}.bak"
        echo_if_not_quiet "  Backed up $HOME/$dotfile"
    fi
done
sep

# Backup authorized_keys for all users (these live outside /etc)
echo_if_not_quiet "Backing up SSH authorized_keys..."
mkdir -p "$backup_dir/authorized_keys"
for home_dir in /root /home/*; do
    if [ -f "$home_dir/.ssh/authorized_keys" ]; then
        username=$(basename "$home_dir")
        cp "$home_dir/.ssh/authorized_keys" "$backup_dir/authorized_keys/${username}_authorized_keys.bak"
        chmod 600 "$backup_dir/authorized_keys/${username}_authorized_keys.bak"
        echo_if_not_quiet "  Backed up $home_dir/.ssh/authorized_keys"
    fi
done
sep

# Backup environment variables
echo_if_not_quiet "Backing up environment variables..."
env > "$backup_dir/environment_variables.bak"
if [ $? -eq 0 ]; then
    chmod 600 "$backup_dir/environment_variables.bak"
    echo_if_not_quiet "Done backing up environment variables."
else
    echo "[!] Error: Failed to create backup for environment variables."
fi
sep

# Backup PATH
echo_if_not_quiet "Backing up PATH..."
echo "$PATH" > "$backup_dir/path.bak"
if [ $? -eq 0 ]; then
    chmod 600 "$backup_dir/path.bak"
    echo_if_not_quiet "Done backing up PATH."
else
    echo "[!] Error: Failed to create backup for PATH."
fi
sep

# Wazuh (lives outside /etc)
if [ -f "/var/ossec/etc/ossec.conf" ]; then
    echo_if_not_quiet "Backing up Wazuh conf..."
    cp /var/ossec/etc/ossec.conf "$backup_dir/ossec.conf"
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/ossec.conf"
        echo_if_not_quiet "Done backing up Wazuh conf."
    else
        echo "[!] Error: Failed to create backup for Wazuh conf."
    fi
fi

echo_if_not_quiet "Baselining network, kernel mods and processes..."

mkdir -p "$backup_dir/baseline"

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

# System identity
cat /etc/os-release > "$backup_dir/baseline/os-release" 2>/dev/null
uname -a > "$backup_dir/baseline/uname" 2>/dev/null
id > "$backup_dir/baseline/id" 2>/dev/null
who > "$backup_dir/baseline/who" 2>/dev/null
w > "$backup_dir/baseline/w" 2>/dev/null
last -50 > "$backup_dir/baseline/last_logins" 2>/dev/null

# Kernel and processes
lsmod > "$backup_dir/baseline/kmods"
ps auxf > "$backup_dir/baseline/processes"

# Network
if command_exists ss; then
    ss -plunt > "$backup_dir/baseline/listening"
    ss -peunt > "$backup_dir/baseline/established"
elif command_exists sockstat; then
    sockstat -4l > "$backup_dir/baseline/listening"
    sockstat -4c > "$backup_dir/baseline/connected"
else
    netstat -an | grep LISTEN > "$backup_dir/baseline/listening"
fi
ip addr > "$backup_dir/baseline/ip_addr" 2>/dev/null
ip route > "$backup_dir/baseline/ip_route" 2>/dev/null

# Services
if command_exists systemctl; then
    systemctl list-unit-files --state=enabled > "$backup_dir/baseline/enabled_services" 2>/dev/null
    systemctl list-units --type=service --state=running > "$backup_dir/baseline/running_services" 2>/dev/null
    systemctl list-timers --all > "$backup_dir/baseline/timers" 2>/dev/null
fi

# Cron (user crontabs live outside /etc)
crontab -l > "$backup_dir/baseline/root_crontab" 2>/dev/null
if [ -d /var/spool/cron ]; then
    tar -czf "$backup_dir/baseline/spool_crontabs.tar.gz" -C /var/spool cron 2>/dev/null
fi

# SUID/SGID binaries (common persistence/privesc vector)
find / -perm -4000 -type f 2>/dev/null > "$backup_dir/baseline/suid_binaries"
find / -perm -2000 -type f 2>/dev/null > "$backup_dir/baseline/sgid_binaries"

echo_if_not_quiet "Done baselining the system at $backup_dir/baseline."
sep

echo "General backup finished. Find files in $backup_dir"

chattr -R +i "$backup_dir"
