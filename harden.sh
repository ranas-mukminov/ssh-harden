#!/usr/bin/env bash
# harden.sh — SSH hardening module (CIS-oriented)
# Usage: ./harden.sh --audit | --apply
# Audit requires read access to /etc/ssh/sshd_config (typically root or ssh group).
# Apply requires root, validates config with sshd -t before replacing the live file.

set -euo pipefail

LOGFILE="/var/log/autoharden-ssh.log"
SSHD_CONF="/etc/ssh/sshd_config"

TIMESTAMP() { date +"%Y%m%d-%H%M%S"; }
DATESTAMP() { date +"%Y-%m-%d %H:%M:%S"; }

declare -A SETTINGS=(
  [PasswordAuthentication]=no
  [PermitRootLogin]=no
  [MaxAuthTries]=3
  [X11Forwarding]=no
  [AllowTcpForwarding]=no
)

log() {
  local msg="$1"
  echo "[$(DATESTAMP)] $msg" | tee -a "$LOGFILE"
}

usage() {
  echo "Usage: $0 --audit | --apply"
  echo "  --audit  Report what would change (needs read access to $SSHD_CONF)"
  echo "  --apply  Backup, validate, then apply changes (requires root)"
  exit 2
}

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
  fi
}

# Refuse dangerous auth lockdown if no usable key auth path is present.
check_key_auth_safe() {
  local invoker="${SUDO_USER:-${USER:-}}"
  local home_dir keys_file
  if [[ -n "$invoker" && "$invoker" != "root" ]]; then
    home_dir=$(getent passwd "$invoker" | cut -d: -f6 || true)
  else
    home_dir="${HOME:-/root}"
  fi
  keys_file="${home_dir}/.ssh/authorized_keys"

  if [[ ! -s "$keys_file" ]]; then
    echo "Refusing to disable password/root login: no non-empty authorized_keys at $keys_file." >&2
    echo "Add a working SSH public key first, then re-run --apply." >&2
    exit 1
  fi
  log "KEY CHECK: found authorized_keys for ${invoker:-unknown} at $keys_file"
}

backup_conf() {
  local ts dest
  ts=$(TIMESTAMP)
  dest="${SSHD_CONF}.autoharden-${ts}"
  cp -a "$SSHD_CONF" "$dest"
  log "BACKUP: $SSHD_CONF -> $dest"
}

set_option_in_file() {
  local key="$1" value="$2" file="$3"
  local escaped_value
  escaped_value=$(printf '%s' "$value" | sed -e 's/[&/\\]/\\\\&/g')

  if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" "$file" \
    || grep -qE "^[[:space:]]*#?[[:space:]]*${key}$" "$file"; then
    sed -ri "0,/^[[:space:]]*#?[[:space:]]*${key}\\b/ s|^[[:space:]]*#?[[:space:]]*${key}.*|${key} ${escaped_value}|" "$file"
  else
    printf '%s %s\n' "$key" "$value" >> "$file"
  fi
}

current_value() {
  local key="$1" file="$2"
  awk -v k="$key" '
    BEGIN { IGNORECASE=1 }
    $0 ~ "^[[:space:]]*" k "[[:space:]]" { print $2; exit }
  ' "$file" || true
}

audit_or_apply_change() {
  local key="$1" value="$2" mode="$3" file="$4"
  local current
  current=$(current_value "$key" "$file")

  if [[ -z "$current" ]]; then
    echo "Would set $key $value (not present)"
    if [[ "$mode" == "apply" ]]; then
      set_option_in_file "$key" "$value" "$file"
      log "SET: $key $value"
    fi
  elif [[ "$current" != "$value" ]]; then
    echo "Would set $key $value (current: $current)"
    if [[ "$mode" == "apply" ]]; then
      set_option_in_file "$key" "$value" "$file"
      log "SET: $key $value (was: $current)"
    fi
  else
    echo "$key already set to $value"
  fi
}

validate_sshd_config() {
  local file="$1"
  local sshd_bin
  sshd_bin=$(command -v sshd || true)
  if [[ -z "$sshd_bin" && -x /usr/sbin/sshd ]]; then
    sshd_bin=/usr/sbin/sshd
  fi
  if [[ -z "$sshd_bin" ]]; then
    echo "sshd binary not found; cannot validate config." >&2
    log "VALIDATE FAILED: sshd not found"
    return 1
  fi
  if "$sshd_bin" -t -f "$file"; then
    log "VALIDATE: sshd -t -f $file -> OK"
    return 0
  fi
  echo "sshd config validation failed for $file" >&2
  log "VALIDATE FAILED: sshd -t -f $file"
  return 1
}

restart_ssh() {
  local services=("sshd" "ssh") svc
  for svc in "${services[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
      if systemctl restart "$svc"; then
        log "RESTART: systemctl restart $svc -> OK"
        if systemctl is-active --quiet "$svc"; then
          echo "SSH service ($svc) restarted successfully."
          return 0
        fi
        echo "SSH service ($svc) restart attempted but service is not active." >&2
        log "RESTART: $svc restarted but not active"
        return 2
      fi
      echo "Failed to restart $svc with systemctl." >&2
      log "RESTART FAILED: systemctl restart $svc"
      return 3
    fi
  done

  if command -v service >/dev/null 2>&1; then
    for svc in "${services[@]}"; do
      if service "$svc" status >/dev/null 2>&1; then
        if service "$svc" restart; then
          log "RESTART: service $svc restart -> OK"
          echo "SSH service ($svc) restarted (sysv)."
          return 0
        fi
        log "RESTART FAILED: service $svc restart"
        echo "Failed to restart $svc with service command." >&2
        return 4
      fi
    done
  fi

  echo "No recognizable SSH service found to restart." >&2
  log "RESTART FAILED: no ssh service found"
  return 5
}

if [[ $# -ne 1 ]]; then
  usage
fi

MODE=""
case "$1" in
  --audit) MODE="audit" ;;
  --apply) MODE="apply" ;;
  *) usage ;;
esac

if [[ ! -r "$SSHD_CONF" ]]; then
  echo "Cannot read $SSHD_CONF (needed for $MODE). Run as a user with read access, usually root." >&2
  exit 1
fi

WORKFILE=""
cleanup() {
  if [[ -n "${WORKFILE:-}" && -f "${WORKFILE:-}" && "$WORKFILE" != "$SSHD_CONF" ]]; then
    rm -f "$WORKFILE"
  fi
}
trap cleanup EXIT

if [[ "$MODE" == "apply" ]]; then
  require_root
  check_key_auth_safe
  mkdir -p "$(dirname "$LOGFILE")"
  touch "$LOGFILE"
  backup_conf
  WORKFILE=$(mktemp /tmp/sshd_config.autoharden.XXXXXX)
  cp -a "$SSHD_CONF" "$WORKFILE"
else
  WORKFILE=$(mktemp /tmp/sshd_config.autoharden.XXXXXX)
  cp -a "$SSHD_CONF" "$WORKFILE"
fi

for key in "${!SETTINGS[@]}"; do
  value="${SETTINGS[$key]}"
  audit_or_apply_change "$key" "$value" "$MODE" "$WORKFILE"
done

if [[ "$MODE" == "apply" ]]; then
  echo
  echo "Validating proposed sshd_config..."
  validate_sshd_config "$WORKFILE"
  # Atomic-ish replace: install preserves mode when possible
  install -m 0644 "$WORKFILE" "$SSHD_CONF"
  log "INSTALL: validated config written to $SSHD_CONF"
  echo "Applying changes and attempting to restart SSH service..."
  # Re-validate live file before restart
  validate_sshd_config "$SSHD_CONF"
  restart_ssh
  ret=$?
  if [[ $ret -eq 0 ]]; then
    echo "All done. Changes logged to $LOGFILE"
    exit 0
  fi
  echo "Restart failed (code $ret). Check $LOGFILE and the service status." >&2
  exit "$ret"
fi

echo
echo "Audit complete. No live files were modified."
echo "Requires read access to $SSHD_CONF. Run with --apply as root to apply."
exit 0
