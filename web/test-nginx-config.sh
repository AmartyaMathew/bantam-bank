#!/bin/sh

set -eu

image="${BANTAM_WEB_TEST_IMAGE:-bantam-web-proxy-test}"
test_dir="$(mktemp -d)"
hardened_container=""

cleanup() {
    if [ -n "$hardened_container" ]; then
        docker rm --force "$hardened_container" >/dev/null 2>&1 || true
    fi
    rm -rf "$test_dir"
}
trap cleanup EXIT HUP INT TERM

docker build --target production --tag "$image" .

# The default edge configuration names the Compose API service. Give the
# isolated config-test container a deterministic address for that name so
# nginx can resolve the otherwise-correct upstream while parsing the config.
docker run --rm \
    --add-host bantam-api:127.0.0.1 \
    "$image" nginx -T >"$test_dir/edge.conf" 2>&1
grep -Fq 'proxy_pass http://bantam-api:8080/;' "$test_dir/edge.conf"
grep -Fq 'proxy_set_header X-Forwarded-For $remote_addr;' "$test_dir/edge.conf"
grep -Fq 'proxy_set_header X-Forwarded-Proto $scheme;' "$test_dir/edge.conf"

docker run --rm \
    --env BANTAM_PROXY_MODE=trusted-edge \
    --env BANTAM_API_UPSTREAM=http://127.0.0.1:8080/ \
    "$image" nginx -T >"$test_dir/trusted-edge.conf" 2>&1
grep -Fq 'proxy_pass http://127.0.0.1:8080/;' "$test_dir/trusted-edge.conf"
grep -Fq \
    'proxy_set_header X-Forwarded-For $http_x_forwarded_for;' \
    "$test_dir/trusted-edge.conf"
grep -Fq \
    'proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;' \
    "$test_dir/trusted-edge.conf"

docker run --rm \
    --env BANTAM_PROXY_MODE=cloud-run \
    --env BANTAM_API_UPSTREAM=http://127.0.0.1:8080/ \
    "$image" nginx -T >"$test_dir/cloud-run.conf" 2>&1
grep -Fq 'proxy_pass http://127.0.0.1:8080/;' "$test_dir/cloud-run.conf"
grep -Fq \
    'proxy_set_header X-Forwarded-For $http_x_forwarded_for;' \
    "$test_dir/cloud-run.conf"
grep -Fq \
    'proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;' \
    "$test_dir/cloud-run.conf"

if docker run --rm \
    --env BANTAM_PROXY_MODE=invalid \
    "$image" nginx -t >"$test_dir/invalid.conf" 2>&1; then
    echo >&2 "invalid BANTAM_PROXY_MODE unexpectedly started Nginx"
    exit 1
fi

# Exercise the production capability and read-only-filesystem boundary, not
# only nginx's rendered configuration.
hardened_container=$(docker run --detach --rm \
    --add-host bantam-api:127.0.0.1 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add SETGID \
    --cap-add SETUID \
    --read-only \
    --tmpfs /etc/nginx/conf.d:size=1m,mode=0755 \
    --tmpfs /var/cache/nginx:size=16m,noexec,nosuid,nodev \
    --tmpfs /var/run:size=1m,noexec,nosuid,nodev \
    --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
    "$image")

ready=false
for _attempt in $(seq 1 20); do
    if docker exec "$hardened_container" \
        wget -q -O - http://127.0.0.1:3000/healthz >/dev/null; then
        ready=true
        break
    fi
    sleep 0.25
done
if [ "$ready" != true ]; then
    docker logs "$hardened_container" >&2
    echo >&2 "hardened Nginx container did not become healthy"
    exit 1
fi
