# How linux-audit works

This document explains the script in plain language: how it is built, what every check reads, how it decides between PASS, WARN and FAIL, and where each check can be wrong.

## The design

`audit.sh` is one Bash file with four parts:

1. **Setup.** It reads the one optional argument (`--json`) and notes whether it runs as root (`id -u` equals 0).
2. **Check functions.** There is one function per check, named `check_...`. A check reads a file or runs a query command, decides on a status, and calls `record STATUS TITLE DETAIL [FIX]`.
3. **Results.** `record` appends to four arrays (statuses, titles, details, fixes). Nothing is printed while the checks run.
4. **Output.** At the end, `print_text` or `print_json` walks through the arrays. Because the results are stored first, both formats always show the same data.

### The four statuses

| Status | Meaning |
|---|---|
| PASS | The setting is as it should be. |
| WARN | Weaker than recommended, or something a person has to review. |
| FAIL | A clear weakness that should be fixed. |
| SKIP | The check could not be done, for example because the file needs root or the tool is not installed. |

SKIP exists so that "not checked" is never mistaken for "fine". The summary counts it separately.

### Why it is safe to run

- The script only uses commands that read: `cat`, `awk`, `grep`, `sed`, `find`, `ss`, `id`, `systemctl is-active`, `systemctl is-enabled`, `sshd -T` and `iptables -S`. None of them changes a setting.
- It writes no files, not even temporary ones.
- It does not use `set -e`, because a check that finds nothing often ends with a non-zero exit code, and that must not stop the script. `set -u` is on, so a mistyped variable name is an error.
- The exit code is 0 whenever the script ran. Findings are results, not errors.

## The checks

### 1. SSH root login

- **Reads:** the `PermitRootLogin` option of the SSH server.
- **Result:** `no` is PASS. `yes` is FAIL. `prohibit-password` (root may log in with a key) or no value at all is WARN, because the OpenSSH default is `prohibit-password`.
- **Why:** if root can log in directly, an attacker only needs one secret to own the machine, and the logs do not show which person was behind the login. Logging in as a normal user and using `sudo` fixes both.
- **How the value is found:** as root the script asks `sshd -T`, which prints the configuration the server really uses. Without root it reads `/etc/ssh/sshd_config.d/*.conf` and then `/etc/ssh/sshd_config` and takes the first value, because sshd also uses the first value it finds.
- **Can be wrong when:** the script runs without root and the configuration uses `Match` blocks or an unusual `Include` order. Then the first value in the files may not be the effective one.
- **SKIP when:** `/etc/ssh/sshd_config` does not exist or is not readable, which normally means no SSH server is installed.

### 2. SSH password authentication

- **Reads:** the `PasswordAuthentication` option, found the same way.
- **Result:** `no` is PASS. `yes` or no value (the default is yes) is WARN.
- **Why:** passwords can be guessed, keys in practice cannot. With password login switched off, SSH brute force stops being a risk.
- **Why WARN and not FAIL:** password login with strong passwords and rate limiting is a weaker choice, not an open door.

### 3. Firewall active

- **Reads:** whether the `ufw`, `firewalld` or `nftables` service is active (`systemctl is-active`). For ufw it also reads `ENABLED=yes` in `/etc/ufw/ufw.conf`, because the service can be running while the firewall is switched off. As root, it also counts the loaded iptables rules.
- **Result:** an active firewall is PASS. As root with nothing found it is FAIL. Without root with nothing found it is WARN, because iptables rules cannot be read without root.
- **Can be wrong when:** the host is protected by a firewall outside the machine, such as a cloud security group. The script cannot see that, so a FAIL here can be acceptable in such a setup. It also does not judge whether the rules are good, only that a firewall is on.

### 4. Automatic security updates

- **Reads:** on Debian and Ubuntu, whether any file in `/etc/apt/apt.conf.d` contains `APT::Periodic::Unattended-Upgrade "1"`. On Fedora and RHEL, whether a `dnf-automatic` timer is enabled.
- **Result:** found is PASS, not found is WARN.
- **Why:** most successful attacks use vulnerabilities for which a fix already exists. Automatic security updates close that gap without anyone having to remember.
- **Can be wrong when:** updates are handled by a central patch management system. Then WARN is a false alarm.

### 5. Duplicate UID 0 accounts

- **Reads:** `/etc/passwd`, third field (the user ID).
- **Result:** only `root` has UID 0 is PASS. Any other account with UID 0 is FAIL.
- **Why:** Linux decides who is root by the number 0, not by the name. A second account with UID 0 is a hidden root account, and it is a classic way for an attacker to keep access.
- **False positives:** very rare. Some old systems have a deliberate second root account such as `toor`.

### 6. Empty passwords

- **Reads:** `/etc/shadow`, second field (the password hash).
- **Result:** no account with an empty field is PASS. Any account with an empty field is FAIL.
- **Why:** an empty field means the account has no password at all. A field containing `!` or `*` is different: that account is locked and cannot log in with a password, which is fine.
- **SKIP when:** `/etc/shadow` is not readable, which is the normal case without root.

### 7. Password ageing defaults

- **Reads:** `PASS_MAX_DAYS` in `/etc/login.defs`, the maximum age of a password for newly created accounts.
- **Result:** 365 or less is PASS. More is WARN. The usual default is 99999, which means "never".
- **Why WARN only:** opinions differ. Current guidance from bodies such as NIST advises against forcing regular password changes without a reason, while many company policies and audit standards still require a maximum age. The check shows the value so that it can be compared with the policy that applies.
- **Limit:** the value only applies to accounts created afterwards. Existing accounts keep their own setting (`chage -l USER`).

### 8. World-writable files in system paths

- **Reads:** `find` in `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin` and `/usr/local/sbin` for regular files that anyone may write (`-perm -0002`).
- **Result:** none is PASS. Any is FAIL, with the count and up to three examples.
- **Why:** if any user can change a program or a configuration file that root uses, any user can become root.
- **Details:** `-xdev` keeps `find` on one filesystem so it does not wander into network mounts. Only regular files are checked; world-writable directories such as `/tmp` are normal.
- **Without root:** directories the user may not enter are silently left out, so the result can be incomplete.

### 9. Unexpected SUID binaries

- **Reads:** `find` in `/usr`, `/bin`, `/sbin` and `/opt` for files with the SUID bit (`-perm -4000`), and compares each file name with a list of programs that normally have it (`sudo`, `su`, `passwd`, `mount` and so on).
- **Result:** everything on the list is PASS. Anything else is WARN, with the paths.
- **Why:** a SUID program runs with the rights of its owner, usually root, no matter who starts it. A mistake in such a program, or a SUID copy of a shell left behind by an attacker, gives root rights to any user.
- **Why WARN:** the list cannot know every distribution and every installed package. An unknown SUID file is something to look at, not proof of a problem.
- **Limit:** the comparison uses the file name only. A malicious file that is named like an expected one, for example a fake `sudo` in an unusual directory, would pass.

### 10. Listening network ports

- **Reads:** `ss -tuln`, the list of TCP and UDP sockets that wait for connections.
- **Result:** if every listener is bound to a loopback address (127.x or ::1) it is PASS. Otherwise WARN, with the list as protocol/port.
- **Why:** every service that listens on the network is a way in. The list should contain only what the host is meant to offer.
- **Why WARN:** the script cannot know which services are intended. A web server listening on 443 is correct, a forgotten database on 5432 is not. A person has to compare the list with the purpose of the host.
- **SKIP when:** the `ss` command is not installed.

## The JSON output

`--json` prints one object with `root` (true or false), `summary` (the four counts) and `checks` (a list of objects with `status`, `check`, `detail` and `fix`). The script builds the JSON by hand with `printf`, and `json_escape` protects backslashes and double quotes in the values. CI pipes the output through a JSON parser to prove it is valid.

## What CI does

1. **ShellCheck.** `shellcheck audit.sh` must report nothing at all. ShellCheck finds common Bash mistakes such as unquoted variables.
2. **JSON test.** The `--json` output is parsed by `python3 -m json.tool`.
3. **Real run.** The script runs on the GitHub Ubuntu runner, once with `sudo` and once without, and both reports go to the job summary. The example in the README is copied from there.

There are no unit tests, because the script's input is the system it runs on. The real run on a clean runner is the test.
