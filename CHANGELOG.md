# Changelog

## [0.1.0] — 2026-09-26

### Added

- `harden.sh` with `--audit` / `--apply` modes
- Defaults: PasswordAuthentication no, PermitRootLogin no, MaxAuthTries 3, X11Forwarding no, AllowTcpForwarding no
- Backup, `sshd -t` validation, authorized_keys lockout guard, service restart helpers
- MIT LICENSE, polished README, GitHub topics

### Notes

- CIS-oriented **examples** only — not a compliance certification.
