#!/usr/bin/env bash
# Install ssh-honeypot as a systemd service under a dedicated user.
#
#   sudo ./deploy/install.sh                 # install or upgrade, do not start
#   sudo ./deploy/install.sh --start         # ... and enable + start the honeypot
#   sudo ./deploy/install.sh --start --dashboard   # ... and the localhost dashboard
#   sudo ./deploy/install.sh --uninstall [--purge]
#
# What it touches (and nothing else):
#   /opt/ssh-honeypot          code + virtualenv (root-owned, read-only for the service)
#   /etc/ssh-honeypot          config.yml and env (created only if missing)
#   /var/lib/ssh-honeypot      database + host keys (created by systemd StateDirectory=)
#   /var/log/ssh-honeypot      sshd-style auth.log (created by systemd LogsDirectory=)
#   /etc/systemd/system/ssh-honeypot.service, ssh-honeypot-dashboard.service
#   system user "sshhoneypot" (no shell, no home, no extra groups)
#
# It does NOT install packages, and it never changes sshd, nginx, the
# firewall, mail or any other service. The honeypot listens on port 2222;
# how (and whether) to expose it is your decision - see DEPLOY.md.

set -euo pipefail

APP=ssh-honeypot
USER_NAME=sshhoneypot
PREFIX=/opt/$APP
CONF_DIR=/etc/$APP
STATE_DIR=/var/lib/$APP
LOG_DIR=/var/log/$APP
UNIT_DIR=/etc/systemd/system
UNITS=("$APP.service" "$APP-dashboard.service")
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

START=0
DASHBOARD=0
UNINSTALL=0
PURGE=0
for arg in "$@"; do
    case "$arg" in
        --start) START=1 ;;
        --dashboard) DASHBOARD=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0 $*)"
command -v systemctl >/dev/null || die "systemd is required for this install method; use Docker instead"

if [[ $UNINSTALL -eq 1 ]]; then
    log "stopping and removing the services"
    for unit in "${UNITS[@]}"; do
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f "${UNIT_DIR:?}/$unit"
    done
    systemctl daemon-reload
    rm -rf "${PREFIX:?}"
    if [[ $PURGE -eq 1 ]]; then
        log "purging configuration, data (database, host keys) and logs"
        rm -rf "${CONF_DIR:?}" "${STATE_DIR:?}" "${LOG_DIR:?}"
        userdel "$USER_NAME" 2>/dev/null || true
    else
        log "kept $CONF_DIR, $STATE_DIR and $LOG_DIR (use --purge to delete them)"
    fi
    exit 0
fi

# --- prerequisites ---------------------------------------------------------------
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || die "python3 not found (apt install python3 python3-venv)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "Python >= 3.11 required, found $("$PY" -V 2>&1). On Ubuntu 22.04 use the Docker setup."
"$PY" -c 'import venv, ensurepip' 2>/dev/null \
    || die "python3-venv is missing (apt install python3-venv), then re-run"

# --- user ----------------------------------------------------------------------------
if ! id "$USER_NAME" >/dev/null 2>&1; then
    log "creating system user $USER_NAME"
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$USER_NAME"
fi

# --- code ----------------------------------------------------------------------------
log "installing code into $PREFIX"
install -d -m 0755 "$PREFIX"
rm -rf "${PREFIX:?}/src"
cp -r "$SRC_DIR/src" "$SRC_DIR/pyproject.toml" "$SRC_DIR/README.md" "$SRC_DIR/LICENSE" "$PREFIX/"
[[ -d "$PREFIX/venv" ]] || "$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet "$PREFIX"
chown -R root:root "$PREFIX"
chmod -R go-w "$PREFIX"

# --- configuration -------------------------------------------------------------------
install -d -m 0750 -o root -g "$USER_NAME" "$CONF_DIR"
if [[ ! -f "$CONF_DIR/config.yml" ]]; then
    log "writing $CONF_DIR/config.yml (listening on 0.0.0.0:2222)"
    sed -e "/^listen:/,/^[^ #]/ s|^  host: .*|  host: 0.0.0.0|" \
        -e "s|^database: .*|database: $STATE_DIR/honeypot.db|" \
        -e "s|^state_dir: .*|state_dir: $STATE_DIR|" \
        -e "s|^auth_log: .*|auth_log: $LOG_DIR/auth.log|" \
        "$SRC_DIR/config.yml" > "$CONF_DIR/config.yml"
    chown root:"$USER_NAME" "$CONF_DIR/config.yml"
    chmod 0640 "$CONF_DIR/config.yml"
else
    log "keeping existing $CONF_DIR/config.yml"
fi
if [[ ! -f "$CONF_DIR/env" ]]; then
    install -m 0640 -o root -g "$USER_NAME" "$SRC_DIR/.env.example" "$CONF_DIR/env"
    log "created $CONF_DIR/env - optional Telegram and dashboard credentials go there"
fi

# --- services ------------------------------------------------------------------------
for unit in "${UNITS[@]}"; do
    install -m 0644 "$SRC_DIR/deploy/$unit" "$UNIT_DIR/$unit"
done
systemctl daemon-reload

log "checking configuration"
(cd / && runuser -u "$USER_NAME" -- env HONEYPOT_CONFIG="$CONF_DIR/config.yml" \
    "$PREFIX/venv/bin/honeypot" check-config) || die "configuration check failed"

port=$(sed -n '/^listen:/,/^[^ #]/ s|^  port: *\([0-9]*\).*|\1|p' "$CONF_DIR/config.yml")
if [[ -n "$port" && "$port" != "2222" ]]; then
    warn "config listens on port $port, but the unit only allows binding 2222:"
    warn "edit SocketBindAllow= in $UNIT_DIR/$APP.service (or use a drop-in) to match"
fi
if command -v ss >/dev/null && ss -Hltn "sport = :${port:-2222}" | grep -q . \
        && ! systemctl is-active --quiet "$APP.service"; then
    warn "something else already listens on port ${port:-2222}; the honeypot will fail to start"
fi

if [[ $START -eq 1 ]]; then
    systemctl enable --now "$APP.service"
    systemctl restart "$APP.service"
    if [[ $DASHBOARD -eq 1 ]]; then
        systemctl enable --now "$APP-dashboard.service"
        systemctl restart "$APP-dashboard.service"
    fi
    log "started; logs: journalctl -u $APP -f"
else
    log "installed. Review $CONF_DIR/config.yml and $CONF_DIR/env, then:"
    echo "      sudo systemctl enable --now $APP"
    echo "      sudo systemctl enable --now $APP-dashboard     # optional"
    echo "      journalctl -u $APP -f"
fi
echo "    Port 2222 is not reachable until your firewall allows it - see DEPLOY.md."
echo "    Dashboard (from your laptop): ssh -N -L 8081:127.0.0.1:8081 <you>@<server>  ->  http://localhost:8081"
