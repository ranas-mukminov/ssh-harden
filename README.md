# ssh-harden

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Homepage](https://img.shields.io/badge/site-run--as--daemon.dev-blue)](https://run-as-daemon.dev)

Minimal **SSH daemon hardening** helper extracted from [AutoHarden-Toolkit](https://github.com/ranas-mukminov/AutoHarden-Toolkit).

> CIS-oriented examples for `sshd_config`. Not a compliance certification. Review before applying on production hosts.

## Quick start

```bash
# Audit (read-only)
sudo ./harden.sh --audit

# Apply (requires root + working authorized_keys — refuses lockout otherwise)
sudo ./harden.sh --apply
```

## What it changes (defaults)

| Setting | Value |
|---------|-------|
| PasswordAuthentication | no |
| PermitRootLogin | no |
| MaxAuthTries | 3 |
| X11Forwarding | no |
| AllowTcpForwarding | no |

Apply backs up `/etc/ssh/sshd_config`, runs `sshd -t`, then reloads. See script comments for safety checks.

## Related

- Full toolkit: [AutoHarden-Toolkit](https://github.com/ranas-mukminov/AutoHarden-Toolkit)
- K8s FinTech baseline: [k8s-fintech-baseline](https://github.com/ranas-mukminov/k8s-fintech-baseline)
- Site: [run-as-daemon.dev](https://run-as-daemon.dev)

## License

MIT © 2026 Run_as_daemon / ranas-mukminov
