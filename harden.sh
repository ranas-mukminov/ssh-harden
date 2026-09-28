#!/usr/bin/env bash
# harden.sh — SSH hardening module (CIS-oriented examples)
# Usage: ./harden.sh --audit | --apply [--force-match]
# Audit requires read access to /etc/ssh/sshd_config (typically root or ssh group).
# Apply requires root, writes a late-loaded drop-in under sshd_config.d, validates
# with sshd -t / effective settings via sshd -T, then reloads sshd.

set -euo pipefail

LOGFILE="/var/log/autoharden-ssh.log"
SSHD_CONF="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/99-autoharden.conf"
FORCE_MATCH=0

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
  echo "Usage: $0 --audit | --apply [--force-match]"
  echo "  --audit         Report effective settings via sshd -T when available"
  echo "  --apply         Write ${DROPIN_FILE} (last Include drop-in), validate, reload"
  echo "  --force-match   Allow --apply even if Match stanzas are present"
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
  if [[ -f "$DROPIN_FILE" ]]; then
    cp -a "$DROPIN_FILE" "${DROPIN_FILE}.autoharden-${ts}"
    log "BACKUP: $DROPIN_FILE -> ${DROPIN_FILE}.autoharden-${ts}"
  fi
}

sshd_bin() {
  local b
  b=$(command -v sshd || true)
  if [[ -z "$b" && -x /usr/sbin/sshd ]]; then
    b=/usr/sbin/sshd
  fi
  printf '%s' "$b"
}

config_has_match() {
  # Match blocks can override globals/drop-ins depending on file order.
  # Plain Include of sshd_config.d is expected on Debian/Ubuntu and is how we apply.
  local f
  if grep -Eq '^[[:space:]]*Match[[:space:]]' "$SSHD_CONF" 2>/dev/null; then
    return 0
  fi
  if [[ -d "$DROPIN_DIR" ]]; then
    shopt -s nullglob
    for f in "$DROPIN_DIR"/*.conf; do
      [[ "$(basename "$f")" == "$(basename "$DROPIN_FILE")" ]] && continue
      if grep -Eq '^[[:space:]]*Match[[:space:]]' "$f" 2>/dev/null; then
        return 0
      fi
    done
  fi
  return 1
}

effective_value() {
  # Prefer sshd -T (effective config). Falls back to first global hit in a file.
  local key="$1"
  local bin dump
  bin=$(sshd_bin)
  if [[ -n "$bin" ]]; then
    if dump=$("$bin" -T 2>/dev/null); then
      awk -v k="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" '
        BEGIN { IGNORECASE=1 }
        tolower($1) == k { print $2; exit }
      ' <<<"$dump"
      return 0
    fi
  fi
  awk -v k="$key" '
    BEGIN { IGNORECASE=1 }
    $0 ~ /^[[:space:]]*Match[[:space:]]/ { exit }
    $0 ~ "^[[:space:]]*" k "[[:space:]]" { print $2; exit }
  ' "$SSHD_CONF" || true
}

write_dropin() {
  mkdir -p "$DROPIN_DIR"
  local umask_old
  umask_old=$(umask)
  umask 077
  {
    echo "# Managed by ssh-harden / AutoHarden — do not edit by hand"
    echo "# Loaded last via Include ${DROPIN_DIR}/*.conf (lexicographic)."
    local key
    for key in PasswordAuthentication PermitRootLogin MaxAuthTries X11Forwarding AllowTcpForwarding; do
      printf '%s %s\n' "$key" "${SETTINGS[$key]}"
    done
  } >"$DROPIN_FILE"
  umask "$umask_old"
  chmod 600 "$DROPIN_FILE"
  # Ensure main config includes drop-ins (Debian/Ubuntu default).
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+.*/sshd_config\.d/\*' "$SSHD_CONF"; then
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+' "$SSHD_CONF"; then
      printf '\nInclude %s/*.conf\n' "$DROPIN_DIR" >>"$SSHD_CONF"
      log "INCLUDE: appended Include ${DROPIN_DIR}/*.conf to $SSHD_CONF"
    else
      echo "Warning: $SSHD_CONF has Include but not ${DROPIN_DIR}/*.conf — drop-in may not load." >&2
      log "INCLUDE WARN: drop-in dir may not be included"
    fi
  fi
  log "DROPIN: wrote $DROPIN_FILE"
}

validate_sshd_config() {
  local file="${1:-}"
  local bin
  bin=$(sshd_bin)
  if [[ -z "$bin" ]]; then
    echo "sshd binary not found; cannot validate config." >&2
    log "VALIDATE FAILED: sshd not found"
    return 1
  fi
  if [[ -n "$file" ]]; then
    if "$bin" -t -f "$file"; then
      log "VALIDATE: sshd -t -f $file -> OK"
      return 0
    fi
    echo "sshd config validation failed for $file" >&2
    log "VALIDATE FAILED: sshd -t -f $file"
    return 1
  fi
  if "$bin" -t; then
    log "VALIDATE: sshd -t -> OK"
    return 0
  fi
  echo "sshd config validation failed" >&2
  log "VALIDATE FAILED: sshd -t"
  return 1
}

assert_effective_settings() {
  local key value current
  local bin dump
  bin=$(sshd_bin)
  [[ -n "$bin" ]] || return 0
  dump=$("$bin" -T 2>/dev/null) || {
    echo "Warning: sshd -T unavailable; skipping effective-value assert." >&2
    return 0
  }
  for key in "${!SETTINGS[@]}"; do
    value="${SETTINGS[$key]}"
    current=$(awk -v k="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" '
      BEGIN { IGNORECASE=1 }
      tolower($1) == k { print $2; exit }
    ' <<<"$dump")
    if [[ -z "$current" ]]; then
      echo "Effective setting missing for $key after apply" >&2
      return 1
    fi
    # sshd -T lowercases yes/no
    if [[ "${current,,}" != "${value,,}" ]]; then
      echo "Effective $key is '$current', expected '$value' (Match/Include may still override)." >&2
      echo "Re-run with a representative sshd -T -C user=,host=,addr= or use --force-match after review." >&2
      return 1
    fi
  done
  return 0
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

MODE=""
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit) MODE="audit"; shift ;;
    --apply) MODE="apply"; shift ;;
    --force-match) FORCE_MATCH=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ -n "$MODE" ]] || usage

if [[ ! -r "$SSHD_CONF" ]]; then
  echo "Cannot read $SSHD_CONF (needed for $MODE). Run as a user with read access, usually root." >&2
  exit 1
fi

if [[ "$MODE" == "apply" && "$FORCE_MATCH" -eq 0 ]] && config_has_match; then
  echo "Refusing --apply: Match blocks found in sshd config." >&2
  echo "Drop-in ${DROPIN_FILE} may still be overridden by later Match stanzas." >&2
  echo "Review with: sshd -T | grep -Ei 'passwordauthentication|permitrootlogin'" >&2
  echo "Re-run with --force-match after confirming effective settings for your hosts." >&2
  exit 1
fi

WORKDIR=""
cleanup() {
  if [[ -n "${WORKDIR:-}" && -d "${WORKDIR:-}" ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

# Private work dir (not world-readable /tmp)
if [[ "$MODE" == "apply" ]]; then
  require_root
  check_key_auth_safe
  mkdir -p "$(dirname "$LOGFILE")"
  touch "$LOGFILE"
  backup_conf
  WORKDIR=$(mktemp -d /root/.ssh-harden.XXXXXX)
else
  if [[ $(id -u) -eq 0 ]]; then
    WORKDIR=$(mktemp -d /root/.ssh-harden.XXXXXX)
  else
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/ssh-harden.XXXXXX")
    chmod 700 "$WORKDIR"
  fi
fi

echo "Desired settings:"
for key in PasswordAuthentication PermitRootLogin MaxAuthTries X11Forwarding AllowTcpForwarding; do
  value="${SETTINGS[$key]}"
  current=$(effective_value "$key")
  if [[ -z "$current" ]]; then
    echo "Would set $key $value (effective value unknown / not present)"
  elif [[ "${current,,}" == "${value,,}" ]]; then
    echo "$key already effective as $value"
  else
    echo "Would set $key $value (effective: $current)"
  fi
done

if [[ "$MODE" == "apply" ]]; then
  echo
  write_dropin
  echo "Validating sshd configuration..."
  validate_sshd_config
  assert_effective_settings || {
    echo "Rolling back drop-in due to effective-value mismatch." >&2
    rm -f "$DROPIN_FILE"
    exit 1
  }
  echo "Applying changes and attempting to restart SSH service..."
  restart_ssh
  ret=$?
  if [[ $ret -eq 0 ]]; then
    echo "All done. Drop-in: $DROPIN_FILE (logged to $LOGFILE)"
    exit 0
  fi
  echo "Restart failed (code $ret). Check $LOGFILE and the service status." >&2
  exit "$ret"
fi

echo
echo "Audit complete. No live files were modified."
echo "Effective values prefer sshd -T. Run with --apply as root to write $DROPIN_FILE."
exit 0
