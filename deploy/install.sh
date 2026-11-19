#!/usr/bin/env bash
# flamejob Phase 1 installer (Ubuntu/Debian). Skeleton — see the Phase 1 spec.
set -euo pipefail

CONF_DIR=/etc/flamejob
DATA_DIR=/var/lib/flamejob

echo "flamejob installer"
echo "=================="

# 1. Dependency checks
command -v hashcat >/dev/null 2>&1 || echo "WARN: hashcat not found on PATH"
command -v nvidia-smi >/dev/null 2>&1 || echo "WARN: nvidia-smi not found (NVIDIA driver?)"

# 2. Database choice
read -rp "Database [local/external] (local): " DBMODE
DBMODE=${DBMODE:-local}
if [ "$DBMODE" = "external" ]; then
  read -rp "Postgres DSN: " DSN
else
  DSN="postgres://flamejob@localhost/flamejob"
  echo "A local Postgres will be initialized (install postgresql separately if absent)."
fi

# 3. Directory type (Phase 5; recorded now, local auth used until then)
read -rp "Directory [none/ad/openldap] (none): " DIRTYPE
DIRTYPE=${DIRTYPE:-none}

# 4. Keys and config
sudo mkdir -p "$CONF_DIR" "$DATA_DIR"
if [ ! -f "$CONF_DIR/jwt.key" ]; then openssl rand -hex 32 | sudo tee "$CONF_DIR/jwt.key" >/dev/null; fi
if [ ! -f "$CONF_DIR/plain.key" ]; then openssl rand -hex 32 | sudo tee "$CONF_DIR/plain.key" >/dev/null; fi

JWT=$(sudo cat "$CONF_DIR/jwt.key")
sudo tee "$CONF_DIR/flamejob.toml" >/dev/null <<TOML
[server]
bind = "0.0.0.0:8443"
[database]
mode = "$DBMODE"
dsn  = "$DSN"
max_connections = 10
[auth]
jwt_secret = "$JWT"
token_ttl_hours = 1
[hashcat]
binary = "$(command -v hashcat || echo /usr/bin/hashcat)"
data_dir = "$DATA_DIR"
workload = 3
[crypto]
plaintext_key_file = "$CONF_DIR/plain.key"
TOML

echo "Directory type recorded: $DIRTYPE (local auth until Phase 5)"
echo "Wrote $CONF_DIR/flamejob.toml"
echo "Next: flamejobd runs migrations on start; then seed the break-glass superadmin."
echo "Install the service with: sudo cp deploy/flamejob-server.service /etc/systemd/system/ && sudo systemctl enable --now flamejob-server"
