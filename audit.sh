#!/usr/bin/env bash
# linux-audit: a read-only check of basic Linux hardening.
#
# Prints PASS, WARN, FAIL or SKIP for each check, a one-line fix hint for
# everything that is not PASS, and a summary. With --json it prints the same
# results as JSON.
#
# The script only reads files and runs query commands. It never changes the
# system. It runs without root and marks what it could not check as SKIP.

set -u

JSON=0
case "${1:-}" in
    --json) JSON=1 ;;
    -h|--help) echo "Usage: $0 [--json]"; exit 0 ;;
    "") ;;
    *) echo "Unknown option: $1 (use --json or --help)" >&2; exit 2 ;;
esac

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

# Results are collected in parallel arrays and printed at the end.
STATUSES=() TITLES=() DETAILS=() FIXES=()

# record STATUS TITLE DETAIL [FIX]
record() {
    STATUSES+=("$1"); TITLES+=("$2"); DETAILS+=("$3"); FIXES+=("${4:-}")
}

# Join the lines on stdin into one comma-separated line.
join_lines() { paste -sd, - | sed 's/,/, /g'; }

# Print the value of an sshd option, lowercased, or nothing if it is not set.
# As root, "sshd -T" gives the effective configuration. Without root the
# config files are read directly; sshd uses the first value it finds, and the
# drop-in directory is included at the top of the main file on most systems.
sshd_option() {
    local name="$1" value=""
    if [ "$IS_ROOT" -eq 1 ] && command -v sshd >/dev/null 2>&1; then
        value="$(sshd -T 2>/dev/null | awk -v n="$name" 'tolower($1) == tolower(n) { print $2; exit }')"
    fi
    if [ -z "$value" ]; then
        value="$(cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
            | awk -v n="$name" 'tolower($1) == tolower(n) { print $2; exit }')"
    fi
    printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
}

check_ssh_root_login() {
    local title="SSH root login" value
    if [ ! -r /etc/ssh/sshd_config ]; then
        record SKIP "$title" "/etc/ssh/sshd_config not found or not readable (is the SSH server installed?)"
        return
    fi
    value="$(sshd_option PermitRootLogin)"
    case "$value" in
        no) record PASS "$title" "PermitRootLogin is 'no'" ;;
        yes) record FAIL "$title" "PermitRootLogin is 'yes'" \
                 "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd" ;;
        "") record WARN "$title" "PermitRootLogin is not set, so root can log in with a key (the default)" \
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd" ;;
        *) record WARN "$title" "PermitRootLogin is '$value', so root can still log in with a key" \
               "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd" ;;
    esac
}

check_ssh_password_auth() {
    local title="SSH password authentication" value
    if [ ! -r /etc/ssh/sshd_config ]; then
        record SKIP "$title" "/etc/ssh/sshd_config not found or not readable (is the SSH server installed?)"
        return
    fi
    value="$(sshd_option PasswordAuthentication)"
    if [ "$value" = "no" ]; then
        record PASS "$title" "PasswordAuthentication is 'no' (keys only)"
    else
        record WARN "$title" "PasswordAuthentication is '${value:-not set (default yes)}', so passwords can be guessed" \
            "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config after setting up SSH keys"
    fi
}

check_firewall() {
    local title="Firewall active" service
    for service in ufw firewalld nftables; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            # The ufw service can be active while the firewall itself is switched off.
            if [ "$service" = "ufw" ] && ! grep -qi '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; then
                continue
            fi
            record PASS "$title" "$service is active"
            return
        fi
    done
    if [ "$IS_ROOT" -eq 1 ] && command -v iptables >/dev/null 2>&1; then
        # More than the three default ACCEPT policies means rules are loaded.
        if [ "$(iptables -S 2>/dev/null | wc -l)" -gt 3 ]; then
            record PASS "$title" "iptables rules are loaded"
        else
            record FAIL "$title" "No active firewall found (ufw, firewalld, nftables, iptables)" \
                "Enable a host firewall, for example: ufw enable"
        fi
    else
        record WARN "$title" "ufw, firewalld and nftables are not active; iptables rules need root to read" \
            "Enable a host firewall (for example: ufw enable), or run this script as root to check iptables"
    fi
}

check_auto_updates() {
    local title="Automatic security updates"
    if grep -qsE 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/* 2>/dev/null; then
        record PASS "$title" "unattended-upgrades is enabled in /etc/apt/apt.conf.d"
    elif systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null \
        || systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null; then
        record PASS "$title" "dnf-automatic timer is enabled"
    else
        record WARN "$title" "No automatic update mechanism found (unattended-upgrades, dnf-automatic)" \
            "Install and enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL)"
    fi
}

check_uid_zero() {
    local title="Duplicate UID 0 accounts" extra
    # Only root should have user ID 0. Any other account with UID 0 is root under another name.
    extra="$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | join_lines)"
    if [ -z "$extra" ]; then
        record PASS "$title" "root is the only account with UID 0"
    else
        record FAIL "$title" "Accounts with UID 0 besides root: $extra" \
            "Remove these accounts or give them a normal UID; use sudo for admin rights"
    fi
}

check_empty_passwords() {
    local title="Empty passwords" empty
    if [ ! -r /etc/shadow ]; then
        record SKIP "$title" "/etc/shadow is not readable without root"
        return
    fi
    # An empty second field in /etc/shadow means the account has no password at all.
    empty="$(awk -F: '$2 == "" { print $1 }' /etc/shadow | join_lines)"
    if [ -z "$empty" ]; then
        record PASS "$title" "No account has an empty password"
    else
        record FAIL "$title" "Accounts with an empty password: $empty" \
            "Set a password (passwd USER) or lock the account (passwd -l USER)"
    fi
}

check_password_ageing() {
    local title="Password ageing defaults" days
    days="$(awk '$1 == "PASS_MAX_DAYS" { print $2; exit }' /etc/login.defs 2>/dev/null)"
    if [ -z "$days" ]; then
        record SKIP "$title" "PASS_MAX_DAYS not found in /etc/login.defs"
    elif [ "$days" -le 365 ] 2>/dev/null; then
        record PASS "$title" "PASS_MAX_DAYS is $days"
    else
        record WARN "$title" "PASS_MAX_DAYS is $days, so new passwords never expire in practice" \
            "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs, following your password policy"
    fi
}

check_world_writable() {
    local title="World-writable files in system paths" found count
    # -perm -0002 matches files that any user may write. -xdev stays on one filesystem.
    found="$(find /etc /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -type f -perm -0002 2>/dev/null)"
    if [ -z "$found" ]; then
        record PASS "$title" "None found in /etc, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    else
        count="$(printf '%s\n' "$found" | wc -l)"
        record FAIL "$title" "$count found, for example: $(printf '%s\n' "$found" | head -n 3 | join_lines)" \
            "Remove the write bit for others: chmod o-w FILE"
    fi
}

# SUID programs that are part of a normal Linux installation.
EXPECTED_SUID=(at chage chfn chsh crontab dbus-daemon-launch-helper expiry fusermount fusermount3
    gpasswd mount mount.cifs mount.nfs newgidmap newgrp newuidmap passwd pkexec polkit-agent-helper-1
    snap-confine ssh-keysign su sudo sudoedit umount unix_chkpwd Xorg.wrap)

check_suid() {
    local title="Unexpected SUID binaries" file unexpected=""
    # A SUID program runs with the rights of its owner (usually root), whoever starts it.
    while IFS= read -r file; do
        if ! printf '%s\n' "${EXPECTED_SUID[@]}" | grep -qxF "$(basename "$file")"; then
            unexpected="${unexpected:+$unexpected, }$file"
        fi
    done < <(find /usr /bin /sbin /opt -xdev -type f -perm -4000 2>/dev/null | sort -u)
    if [ -z "$unexpected" ]; then
        record PASS "$title" "All SUID binaries are on the list of expected system programs"
    else
        record WARN "$title" "Not on the expected list: $unexpected" \
            "Check each file; if SUID is not needed remove it: chmod u-s FILE"
    fi
}

check_listening_ports() {
    local title="Listening network ports" open
    if ! command -v ss >/dev/null 2>&1; then
        record SKIP "$title" "The ss command is not installed"
        return
    fi
    # Column 5 of "ss -tuln" is the local address:port. Loopback-only listeners
    # (127.x and ::1) cannot be reached from the network, so they are left out.
    open="$(ss -H -tuln 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\])/ { n = split($5, a, ":"); print $1 "/" a[n] }' \
        | sort -u | join_lines)"
    if [ -z "$open" ]; then
        record PASS "$title" "Nothing is listening on a network-reachable address"
    else
        record WARN "$title" "Reachable from the network: $open" \
            "Stop services you do not need, or bind them to 127.0.0.1"
    fi
}

# Escape a string for use inside JSON double quotes.
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/ /g'; }

# Count how many results have the given status.
count_status() {
    local wanted="$1" status n=0
    for status in "${STATUSES[@]}"; do
        [ "$status" = "$wanted" ] && n=$((n + 1))
    done
    echo "$n"
}

print_text() {
    local i os
    os="$(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release 2>/dev/null)"
    echo "linux-audit report (${os:-unknown Linux})"
    if [ "$IS_ROOT" -eq 1 ]; then
        echo "Running as root: all checks available."
    else
        echo "Running without root: checks that need root are marked SKIP."
    fi
    echo
    for i in "${!STATUSES[@]}"; do
        printf '[%s] %s: %s\n' "${STATUSES[$i]}" "${TITLES[$i]}" "${DETAILS[$i]}"
        [ -n "${FIXES[$i]}" ] && printf '       Fix: %s\n' "${FIXES[$i]}"
    done
    echo
    echo "Summary: $(count_status PASS) PASS, $(count_status WARN) WARN, $(count_status FAIL) FAIL, $(count_status SKIP) SKIP"
}

print_json() {
    local i last=$(( ${#STATUSES[@]} - 1 ))
    printf '{\n  "root": %s,\n  "summary": {"pass": %s, "warn": %s, "fail": %s, "skip": %s},\n  "checks": [\n' \
        "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)" \
        "$(count_status PASS)" "$(count_status WARN)" "$(count_status FAIL)" "$(count_status SKIP)"
    for i in "${!STATUSES[@]}"; do
        printf '    {"status": "%s", "check": "%s", "detail": "%s", "fix": "%s"}%s\n' \
            "${STATUSES[$i]}" "$(json_escape "${TITLES[$i]}")" "$(json_escape "${DETAILS[$i]}")" \
            "$(json_escape "${FIXES[$i]}")" "$([ "$i" -lt "$last" ] && echo ,)"
    done
    printf '  ]\n}\n'
}

check_ssh_root_login
check_ssh_password_auth
check_firewall
check_auto_updates
check_uid_zero
check_empty_passwords
check_password_ageing
check_world_writable
check_suid
check_listening_ports

if [ "$JSON" -eq 1 ]; then print_json; else print_text; fi
# Findings are results, not errors, so the exit code is 0 whenever the script ran.
exit 0
