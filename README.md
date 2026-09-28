# ssh-harden

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/ranas-mukminov/ssh-harden)](https://github.com/ranas-mukminov/ssh-harden/releases)
[![Homepage](https://img.shields.io/badge/site-run--as--daemon.dev-blue)](https://run-as-daemon.dev)

Minimal **SSH daemon hardening** helper extracted from [AutoHarden-Toolkit](https://github.com/ranas-mukminov/AutoHarden-Toolkit).

> CIS-oriented **examples** for `sshd_config`. Not a compliance certification. Review before applying on production hosts. Always keep a working out-of-band console / second session when changing SSH.

## Quick start

```bash
git clone https://github.com/ranas-mukminov/ssh-harden.git
cd ssh-harden
chmod +x harden.sh

# Audit (read-only) — needs read access to /etc/ssh/sshd_config
sudo ./harden.sh --audit

# Apply — requires root + non-empty authorized_keys (refuses lockout otherwise)
sudo ./harden.sh --apply
# If Match/Include present and you reviewed sshd -T:
# sudo ./harden.sh --apply --force-match
```

## What it changes (defaults)

| Setting | Value | Why (brief) |
|---------|-------|-------------|
| PasswordAuthentication | no | Prefer key-based auth |
| PermitRootLogin | no | No direct root SSH |
| MaxAuthTries | 3 | Limit brute-force attempts |
| X11Forwarding | no | Reduce attack surface |
| AllowTcpForwarding | no | Discourage tunnel misuse |

Apply backs up `/etc/ssh/sshd_config`, edits a temp copy, runs `sshd -t`, installs the validated file, then reloads `sshd`/`ssh`. See script comments for safety checks.

## Safety behavior

- **`--apply` refuses** if the invoking user’s `~/.ssh/authorized_keys` is missing or empty (avoids locking yourself out when disabling passwords).
- Writes a late-loaded drop-in `/etc/ssh/sshd_config.d/99-autoharden.conf` instead of rewriting the first matching line in the vendor file (avoids clobbering `Match` blocks).
- **`--apply` refuses** when `Match` blocks are present unless `--force-match` is set (Debian `Include sshd_config.d` is expected and used for the drop-in). Verify with `sshd -T` (and `sshd -T -C …` for representative Match cases).
- Audit reports **effective** values via `sshd -T` when available (not a single-file first-line read).
- Validates with `sshd -t` before reload; backs up main config and any prior drop-in.
- Work files use a private `mktemp -d` (mode `0700`), not a world-readable `/tmp` copy of `sshd_config`.
- Logs to `/var/log/autoharden-ssh.log` on apply.

## Requirements

- Linux with OpenSSH server (`sshd`)
- Bash 4+ (associative arrays)
- Root for `--apply`; read access to `sshd_config` for `--audit`


## When to use ssh-harden vs AutoHarden

| Tool | Role |
|------|------|
| **ssh-harden** (this repo) | Narrow OpenSSH `sshd_config` helper |
| [AutoHarden-Toolkit](https://github.com/ranas-mukminov/AutoHarden-Toolkit) | Profile CLI (`smb-default`), sysctl/packages/UFW, director MD/PDF report |

ssh-harden is a **subset / optional helper**, not a full CIS suite and not a replacement for AutoHarden.

### Suggested order (K3s Starter / pre-join)

```text
SSH keys → ssh-harden --audit/--apply (optional)
        → AutoHarden dry-run → approve → AutoHarden --apply
        → k3s join (Secure-K3s-GitOps-Template)
```

- AutoHarden pre-join doc (A4): [k3s-pre-join-bootstrap.md](https://github.com/ranas-mukminov/AutoHarden-Toolkit/blob/main/docs/k3s-pre-join-bootstrap.md)
- Template: [Secure-K3s-GitOps-Template](https://github.com/ranas-mukminov/Secure-K3s-GitOps-Template)
- Tracking: [ssh-harden#1](https://github.com/ranas-mukminov/ssh-harden/issues/1)

## Related

- Full toolkit: [AutoHarden-Toolkit](https://github.com/ranas-mukminov/AutoHarden-Toolkit) · [K3s pre-join (A4)](https://github.com/ranas-mukminov/AutoHarden-Toolkit/blob/main/docs/k3s-pre-join-bootstrap.md)
- K3s Starter: [Secure-K3s-GitOps-Template](https://github.com/ranas-mukminov/Secure-K3s-GitOps-Template)
- Kubernetes FinTech baseline: [k8s-fintech-baseline](https://github.com/ranas-mukminov/k8s-fintech-baseline)
- Site: [run-as-daemon.dev](https://run-as-daemon.dev) · [run-as-daemon.ru](https://run-as-daemon.ru)

## Contributing / security

Issues and PRs welcome for safer defaults and clearer docs. Do not open public issues that include production host inventory or credentials.

## License

MIT © 2026 Run_as_daemon / ranas-mukminov — see [`LICENSE`](LICENSE).

---

### If this helped — star the repo

[⭐ Star ranas-mukminov/ssh-harden](https://github.com/ranas-mukminov/ssh-harden) · also [k8s-fintech-baseline](https://github.com/ranas-mukminov/k8s-fintech-baseline)
