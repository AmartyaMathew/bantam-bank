#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file="$script_dir/compose.yml"
config_file=$(mktemp)
trap 'rm -f "$config_file"' EXIT HUP INT TERM

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [production.env]" >&2
    exit 2
fi

if [ "$#" -eq 1 ]; then
    if [ ! -f "$1" ]; then
        echo "environment file not found: $1" >&2
        exit 2
    fi
    docker compose --env-file "$1" -f "$compose_file" \
        config --format json >"$config_file"
else
    : "${BANTAM_DOMAIN:=bantam.example.test}"
    : "${ACME_EMAIL:=operator@example.test}"
    : "${BANTAM_IMAGE_TAG:=compose-validation}"
    : "${BANTAM_API_IMAGE:=bantam-api:compose-validation}"
    : "${BANTAM_WEB_IMAGE:=bantam-web:compose-validation}"
    : "${POSTGRES_PASSWORD:=compose-validation-postgres}"
    : "${NATS_PASSWORD:=compose-validation-nats}"
    : "${NATS_JETSTREAM_KEY:=compose-validation-jetstream}"
    : "${JWT_SECRET:=compose-validation-jwt}"
    : "${SCA_SECRET:=compose-validation-sca}"
    : "${CLAIMS_SECRET:=compose-validation-claims}"
    : "${MFA_ENCRYPTION_KEY:=compose-validation-mfa}"
    export BANTAM_DOMAIN ACME_EMAIL BANTAM_IMAGE_TAG
    export BANTAM_API_IMAGE BANTAM_WEB_IMAGE POSTGRES_PASSWORD
    export NATS_PASSWORD NATS_JETSTREAM_KEY JWT_SECRET SCA_SECRET
    export CLAIMS_SECRET MFA_ENCRYPTION_KEY
    docker compose -f "$compose_file" config --format json >"$config_file"
fi

python3 - "$config_file" "$script_dir" <<'PY'
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import sys


config_path = Path(sys.argv[1])
deployment_dir = Path(sys.argv[2])
config = json.loads(config_path.read_text())
services = config["services"]
networks = config["networks"]

egress_subnet = networks["egress"]["ipam"]["config"][0]["subnet"]
egress_network = ipaddress.ip_network(egress_subnet)
assert egress_subnet == "172.27.0.0/24", egress_subnet
assert egress_network.is_private, egress_subnet
assert networks["app"]["internal"] is True
assert networks["data"]["internal"] is True

published: list[tuple[str, int, str]] = []
for service_name, service in services.items():
    for port in service.get("ports", []):
        published.append(
            (service_name, int(port["published"]), port.get("protocol", "tcp"))
        )
assert sorted(published) == [
    ("caddy", 80, "tcp"),
    ("caddy", 443, "tcp"),
], published

assert set(services["bantam-api"]["networks"]) == {"app", "data", "egress"}
for worker in ("outbox-publisher", "risk-worker", "notification-worker"):
    assert set(services[worker]["networks"]) == {"data"}
    assert services[worker]["depends_on"]["migrate"]["condition"] == (
        "service_completed_successfully"
    )
assert services["bantam-api"]["depends_on"]["migrate"]["condition"] == (
    "service_completed_successfully"
)
assert services["migrate"]["restart"] == "no"
assert services["migrate"]["environment"]["APP_ENV"] == "production"
assert "postgres:5432/bantam" in services["migrate"]["environment"]["DATABASE_URL"]
assert services["bantam-api"]["environment"]["DEMO_MODE"] == "false"
assert services["bantam-api"]["environment"]["ALLOW_DEMO_SEED"] == "false"
assert services["web"]["build"]["target"] == "production"

long_lived = {
    "caddy",
    "web",
    "bantam-api",
    "outbox-publisher",
    "risk-worker",
    "notification-worker",
    "postgres",
    "nats",
}
memory_bytes = sum(int(services[name]["mem_limit"]) for name in long_lived)
assert memory_bytes <= 2 * 1024**3, memory_bytes

assert services["caddy"]["cap_drop"] == ["ALL"]
assert services["caddy"]["cap_add"] == ["NET_BIND_SERVICE"]
assert services["web"]["cap_drop"] == ["ALL"]
assert set(services["web"]["cap_add"]) == {"CHOWN", "SETGID", "SETUID"}
assert "http://127.0.0.1:3000/healthz" in services["web"]["healthcheck"]["test"]
assert any(
    value.startswith("/etc/nginx/conf.d:") and "mode=0755" in value
    for value in services["web"]["tmpfs"]
)

caddyfile = (deployment_dir / "Caddyfile").read_text()
assert "protocols h1 h2" in caddyfile
assert "header_up X-Forwarded-For {remote_host}" in caddyfile
assert "header_up X-Forwarded-Proto {scheme}" in caddyfile
nats_config = (deployment_dir / "nats" / "nats.conf").read_text()
assert "max_file_store: 1G" in nats_config

print(f"DigitalOcean deployment validated ({memory_bytes // 1024**2} MiB capped)")
PY
