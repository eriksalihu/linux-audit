# linux-audit

One read-only Bash script that checks the basic hardening of a Linux host and prints PASS, WARN or FAIL for each check, with a one-line fix hint.

[![CI](https://github.com/eriksalihu/linux-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/eriksalihu/linux-audit/actions/workflows/ci.yml)

## Why a SOC analyst would use it

When a host shows up in an alert, it helps to know quickly how well it was protected in the first place: could root log in over SSH, was a firewall on, is anything listening that should not be? linux-audit answers ten such questions in a few seconds. It is a single file with no dependencies, it never changes the system, and it also runs without root, so it is safe to run on a machine that is under investigation or that belongs to someone else.

## Features

- Ten checks: SSH root login, SSH password authentication, firewall, automatic security updates, duplicate UID 0 accounts, empty passwords, password ageing, world-writable system files, unexpected SUID binaries, listening network ports
- PASS, WARN or FAIL for each check, a one-line fix hint for everything that is not PASS, and a summary
- SKIP for anything it could not check, so "not checked" is never shown as "fine"
- `--json` output for scripts
- Read-only: it only reads files and runs query commands
- Runs without root, and checks more when run as root
- Plain Bash and standard tools, checked by ShellCheck in CI

## Quick start

```bash
git clone https://github.com/eriksalihu/linux-audit.git
cd linux-audit
bash audit.sh              # without root
sudo bash audit.sh         # all checks
sudo bash audit.sh --json  # JSON output
```

## Example output

Copied from the job summary of this repository's CI run. The host is the GitHub-hosted Ubuntu runner, a short-lived build machine, so several warnings are expected there.

As root:

```text
linux-audit report (Ubuntu 24.04.5 LTS)
Running as root: all checks available.

[WARN] SSH root login: PermitRootLogin is not set, so root can log in with a key (the default)
       Fix: Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd
[PASS] SSH password authentication: PasswordAuthentication is 'no' (keys only)
[PASS] Firewall active: iptables rules are loaded
[WARN] Automatic security updates: No automatic update mechanism found (unattended-upgrades, dnf-automatic)
       Fix: Install and enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL)
[PASS] Duplicate UID 0 accounts: root is the only account with UID 0
[PASS] Empty passwords: No account has an empty password
[WARN] Password ageing defaults: PASS_MAX_DAYS is 99999, so new passwords never expire in practice
       Fix: Set PASS_MAX_DAYS to 365 or less in /etc/login.defs, following your password policy
[FAIL] World-writable files in system paths: 13 found, for example: /usr/local/bin/cpack, /usr/local/bin/cmake, /usr/local/bin/stack
       Fix: Remove the write bit for others: chmod o-w FILE
[PASS] Unexpected SUID binaries: All SUID binaries in the program directories are on the expected list
[WARN] Listening network ports: Reachable from the network: tcp/22, udp/68
       Fix: Stop services you do not need, or bind them to 127.0.0.1

Summary: 5 PASS, 4 WARN, 1 FAIL, 0 SKIP
```

The same host without root:

```text
linux-audit report (Ubuntu 24.04.5 LTS)
Running without root: checks that need root are marked SKIP.

[WARN] SSH root login: PermitRootLogin is not set, so root can log in with a key (the default)
       Fix: Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd
[PASS] SSH password authentication: PasswordAuthentication is 'no' (keys only)
[WARN] Firewall active: ufw, firewalld and nftables are not active; iptables rules need root to read
       Fix: Enable a host firewall (for example: ufw enable), or run this script as root to check iptables
[WARN] Automatic security updates: No automatic update mechanism found (unattended-upgrades, dnf-automatic)
       Fix: Install and enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL)
[PASS] Duplicate UID 0 accounts: root is the only account with UID 0
[SKIP] Empty passwords: /etc/shadow is not readable without root
[WARN] Password ageing defaults: PASS_MAX_DAYS is 99999, so new passwords never expire in practice
       Fix: Set PASS_MAX_DAYS to 365 or less in /etc/login.defs, following your password policy
[FAIL] World-writable files in system paths: 13 found, for example: /usr/local/bin/cpack, /usr/local/bin/cmake, /usr/local/bin/stack
       Fix: Remove the write bit for others: chmod o-w FILE
[PASS] Unexpected SUID binaries: All SUID binaries in the program directories are on the expected list
[WARN] Listening network ports: Reachable from the network: tcp/22, udp/68
       Fix: Stop services you do not need, or bind them to 127.0.0.1

Summary: 3 PASS, 5 WARN, 1 FAIL, 1 SKIP
```

## How each check works

| Check | What it reads | FAIL or WARN when |
|---|---|---|
| SSH root login | `PermitRootLogin` from `sshd -T` (root) or the sshd config files | FAIL if `yes`; WARN if key-only root login is allowed or the option is not set |
| SSH password authentication | `PasswordAuthentication`, found the same way | WARN unless it is `no` |
| Firewall active | ufw, firewalld or nftables service state; iptables rules as root | FAIL as root if none is active; WARN without root if none is found |
| Automatic security updates | unattended-upgrades setting in `/etc/apt/apt.conf.d`, or a dnf-automatic timer | WARN if neither is enabled |
| Duplicate UID 0 accounts | `/etc/passwd` | FAIL if any account other than root has UID 0 |
| Empty passwords | `/etc/shadow` (needs root) | FAIL if an account has an empty password field |
| Password ageing defaults | `PASS_MAX_DAYS` in `/etc/login.defs` | WARN if it is more than 365 |
| World-writable files | `find` in `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin` | FAIL if any regular file is writable by everyone |
| Unexpected SUID binaries | `find` for SUID files in the program directories, compared with a list of expected names | WARN if a SUID file is not on the list |
| Listening network ports | `ss -tuln` | WARN if anything listens on a non-loopback address, with the list |

The reasoning behind each check and where it can be wrong is in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## Limitations

- It checks ten basics. It is not a replacement for a full benchmark such as CIS or for a tool such as Lynis.
- It reports settings, not whether the host has been compromised.
- Without root, the empty-password check is skipped, iptables rules cannot be read, and the SSH checks are skipped if any SSH config file is unreadable. The SSH values then come from reading the config files, which can differ from the effective configuration that `sshd -T` shows to root, so run it as root for a reliable SSH answer.
- The firewall check only sees a firewall on the host itself, not a cloud security group or a network firewall in front of it.
- The SUID check looks in the usual program directories and compares file names only. A SUID file somewhere else, or one that uses an expected name, is not flagged.
- The listening-ports check cannot know which services are intended. It lists them for a person to review.
- Written for Debian, Ubuntu, Fedora and RHEL style systems. It is tested in CI on Ubuntu only.

## Next steps

- Add an option to search the whole filesystem for SUID files
- Add checks for sudo configuration, file permissions on `/etc/shadow`, and kernel settings such as ASLR
- Add an allowlist file for expected listening ports
- Test on Fedora and Debian in CI with containers

## License

[MIT](LICENSE)
