#!/usr/bin/env bash
set -e

PG_VER=$(pg_config --version 2>/dev/null | awk '{print $2}' | cut -d. -f1 || echo "17")
PGDATA="/var/lib/postgresql/${PG_VER}/main"
PGBIN="/usr/lib/postgresql/${PG_VER}/bin"
CONF="/etc/postgresql/${PG_VER}/main/postgresql.conf"
HBA="/etc/postgresql/${PG_VER}/main/pg_hba.conf"
INIT_SQL="/poc/postgres/init.sql"

mkdir -p "$PGDATA"
chown -R postgres:postgres /var/lib/postgresql

if [ ! -f "$PGDATA/PG_VERSION" ]; then
    echo "Initializing PostgreSQL cluster (${PG_VER})..."
    su - postgres -c "$PGBIN/initdb -D $PGDATA --auth-local=trust --auth-host=trust"
    echo "listen_addresses = '*'" >> "$CONF"
fi

# Ensure the host-based auth rules the lab needs are present (idempotent).
grep -qF "host all all 127.0.0.1/32 trust" "$HBA" || echo "host all all 127.0.0.1/32 trust" >> "$HBA"
grep -qF "local all all trust"             "$HBA" || echo "local all all trust" >> "$HBA"
grep -qF "host all all 0.0.0.0/0 md5"       "$HBA" || echo "host all all 0.0.0.0/0 md5" >> "$HBA"

# Apply init.sql once, whenever the application database is not yet present. This
# covers a fresh cluster and a base image that ships a pre-initialised but empty
# cluster (where PG_VERSION already exists).
echo "Starting temporary postgres instance to check lab schema..."
su - postgres -c "$PGBIN/pg_ctl -D $PGDATA -o '-c config_file=$CONF' -w start"

if su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='appdb'\"" | grep -q 1; then
    echo "Lab database 'appdb' already present; skipping init.sql."
elif [ -f "$INIT_SQL" ]; then
    echo "Executing $INIT_SQL..."
    su - postgres -c "psql -f $INIT_SQL"
fi

# Apply any migrations present in /poc/postgres/migrations (idempotent)
if [ -d "/poc/postgres/migrations" ]; then
    for mig in /poc/postgres/migrations/*.sql; do
        if [ -f "$mig" ]; then
            echo "Applying migration $mig..."
            su - postgres -c "psql -f $mig" || true
        fi
    done
fi

echo "Stopping temporary postgres instance..."
su - postgres -c "$PGBIN/pg_ctl -D $PGDATA stop -m fast"

echo "Starting PostgreSQL in foreground..."
exec su - postgres -c "$PGBIN/postgres -D $PGDATA -c config_file=$CONF -c listen_addresses='*'"
