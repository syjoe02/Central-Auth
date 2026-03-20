#!/bin/bash
# Creates the kratos and hydra logical databases on the shared Postgres instance.
# This script is mounted into /docker-entrypoint-initdb.d/ and runs once on
# the first container start (before the main database is fully initialised).
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE kratos;
    CREATE DATABASE hydra;
    GRANT ALL PRIVILEGES ON DATABASE kratos TO $POSTGRES_USER;
    GRANT ALL PRIVILEGES ON DATABASE hydra TO $POSTGRES_USER;
EOSQL

echo "init-postgres: kratos and hydra databases created."
