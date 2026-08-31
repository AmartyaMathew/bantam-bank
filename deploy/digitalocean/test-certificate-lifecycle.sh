#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_root=$(mktemp -d)
deployment="$test_root/digitalocean"
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

cp -R "$script_dir" "$deployment"
chmod +x "$deployment/prepare.sh" "$deployment/validate-deployment.sh"

"$deployment/prepare.sh" bantam.example.test operator@example.test
ca_initial=$(openssl x509 -in "$deployment/runtime/tls/ca/ca.crt" \
    -noout -fingerprint -sha256)
postgres_initial=$(openssl x509 \
    -in "$deployment/runtime/tls/postgres/postgres.crt" \
    -noout -fingerprint -sha256)

"$deployment/prepare.sh" --rotate-certs
ca_after_leaf=$(openssl x509 -in "$deployment/runtime/tls/ca/ca.crt" \
    -noout -fingerprint -sha256)
postgres_after_leaf=$(openssl x509 \
    -in "$deployment/runtime/tls/postgres/postgres.crt" \
    -noout -fingerprint -sha256)
[ "$ca_initial" = "$ca_after_leaf" ]
[ "$postgres_initial" != "$postgres_after_leaf" ]

"$deployment/prepare.sh" --rotate-ca
ca_after_root=$(openssl x509 -in "$deployment/runtime/tls/ca/ca.crt" \
    -noout -fingerprint -sha256)
[ "$ca_after_leaf" != "$ca_after_root" ]

openssl x509 -in "$deployment/runtime/tls/postgres/postgres.crt" \
    -noout -ext subjectAltName | grep -Fq 'DNS:postgres'
openssl x509 -in "$deployment/runtime/tls/nats/nats.crt" \
    -noout -ext subjectAltName | grep -Fq 'DNS:nats'

previous_count=$(find "$deployment/runtime" -maxdepth 1 \
    -type d -name 'tls.previous.*' | wc -l | tr -d ' ')
[ "$previous_count" -eq 2 ]

"$deployment/validate-deployment.sh" "$deployment/production.env"
echo "DigitalOcean certificate lifecycle validated"
