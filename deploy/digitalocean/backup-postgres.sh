#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
env_file="$script_dir/production.env"
compose_file="$script_dir/compose.yml"
backup_dir=${1:-"$script_dir/runtime/backups"}
retention_days=${BACKUP_RETENTION_DAYS:-14}

if [ ! -f "$env_file" ]; then
    echo "$env_file is missing; run prepare.sh first" >&2
    exit 1
fi
case "$backup_dir" in
    ""|/|.)
        echo "refusing unsafe backup directory: $backup_dir" >&2
        exit 2
        ;;
esac
case "$retention_days" in
    ""|*[!0-9]*)
        echo "BACKUP_RETENTION_DAYS must be a non-negative integer" >&2
        exit 2
        ;;
esac

umask 077
mkdir -p "$backup_dir"
chmod 0700 "$backup_dir"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_file="$backup_dir/bantam-$timestamp.dump"
partial_file="$backup_file.partial"
trap 'rm -f "$partial_file"' EXIT HUP INT TERM

docker compose --env-file "$env_file" -f "$compose_file" \
    exec -T postgres \
    pg_dump --username=bantam --dbname=bantam --format=custom \
        --no-owner --no-privileges >"$partial_file"

mv "$partial_file" "$backup_file"
sha256sum "$backup_file" >"$backup_file.sha256"
echo "Created $backup_file"

# Prune only Bantam dump files in the explicitly resolved backup directory.
# Partial files and unrelated operator files are deliberately left untouched.
find "$backup_dir" -maxdepth 1 -type f \
    \( -name 'bantam-*.dump' -o -name 'bantam-*.dump.sha256' \) \
    -mtime "+$retention_days" -delete
echo "Applied the $retention_days-day Bantam backup retention policy"
