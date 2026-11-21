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

# 2b. Require PostgreSQL 16 — a 16+ server for external, or an installed PG 16 locally.
pg_major=""
if [ "$DBMODE" = "external" ]; then
  # Ask the server its version through the DSN (needs psql present and reachable).
  if command -v psql >/dev/null 2>&1; then
    vnum=$(psql "$DSN" -tAc 'SHOW server_version_num;' 2>/dev/null | tr -cd '0-9' || true)
    [ -n "$vnum" ] && pg_major=$(( vnum / 10000 ))
  fi
else
  # Local: the server may not be running yet, so look for an installed PG 16.
  for v in $(ls -1 /usr/lib/postgresql 2>/dev/null | sort -rn); do
    [ -x "/usr/lib/postgresql/$v/bin/postgres" ] && { pg_major="$v"; break; }
  done
  if [ -z "$pg_major" ] && command -v pg_config >/dev/null 2>&1; then
    pg_major=$(pg_config --version 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)
  fi
  if [ -z "$pg_major" ] && command -v psql >/dev/null 2>&1; then
    pg_major=$(psql --version 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)
  fi
fi

if [ -n "$pg_major" ] && [ "$pg_major" -ge 16 ] 2>/dev/null; then
  echo "PostgreSQL $pg_major detected — continuing."
else
  echo >&2
  echo "ERROR: PostgreSQL 16 was not detected." >&2
  if [ "$DBMODE" = "external" ]; then
    echo "  Could not confirm the server at the given DSN is PostgreSQL 16 or newer" >&2
    echo "  (psql missing, server unreachable, or an older version)." >&2
    echo "  Point the DSN at a PostgreSQL 16+ server, or install the psql client so this" >&2
    echo "  check can verify it." >&2
  else
    echo "  No local PostgreSQL 16 install was found. Ubuntu 22.04 ships 14 by default;" >&2
    echo "  add the PGDG repo (apt.postgresql.org) and install postgresql-16, or re-run with" >&2
    echo "  Database=external pointing at a 16+ server." >&2
  fi
  echo "  To bypass this check for a known-good setup it cannot see, re-run with" >&2
  echo "  FLAMEJOB_SKIP_PG_CHECK=1." >&2
  if [ "${FLAMEJOB_SKIP_PG_CHECK:-}" = "1" ]; then
    echo "FLAMEJOB_SKIP_PG_CHECK=1 set — continuing despite the warning." >&2
  else
    exit 1
  fi
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
