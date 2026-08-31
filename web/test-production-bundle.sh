#!/bin/sh
set -eu

if [ ! -d dist ]; then
    echo >&2 "production bundle is missing; run npm run build first"
    exit 1
fi

for forbidden in \
    'BantamDemo123!' \
    'alice@bantam.local' \
    'bob@bantam.local' \
    'admin@bantam.local' \
    'risk@bantam.local' \
    'auditor@bantam.local'
do
    if grep -R -F -- "$forbidden" dist >/dev/null; then
        echo >&2 "production bundle contains a deterministic demo credential: $forbidden"
        exit 1
    fi
done

echo "Production bundle contains no deterministic demo credentials."
