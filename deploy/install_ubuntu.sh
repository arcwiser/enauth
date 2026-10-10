#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root: sudo ./deploy/install_ubuntu.sh" >&2
  exit 1
fi

if [[ ! -f "docker-compose.yml" || ! -f ".env.example" ]]; then
  echo "Run this script from the EnAuth repository root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl openssl docker.io

if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y docker-compose-v2 || apt-get install -y docker-compose-plugin
fi

systemctl enable --now docker

env_file=".env"
if [[ ! -f "${env_file}" ]]; then
  cp .env.example "${env_file}"
  chmod 600 "${env_file}"
fi

replace_setting() {
  local key="$1"
  local value="$2"
  local escaped_value
  escaped_value="$(printf '%s' "${value}" | sed 's/[&|]/\\&/g')"
  if grep -q "^${key}=" "${env_file}"; then
    sed -i "s|^${key}=.*$|${key}=${escaped_value}|" "${env_file}"
  else
    printf '%s=%s\n' "${key}" "${value}" >> "${env_file}"
  fi
}

if grep -Eq '^LICENSE_LOOKUP_KEY=(|replace-with-)' "${env_file}"; then
  replace_setting "LICENSE_LOOKUP_KEY" "$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')"
fi
if grep -Eq '^LICENSE_ENCRYPTION_KEY=(|replace-with-)' "${env_file}"; then
  replace_setting "LICENSE_ENCRYPTION_KEY" "$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')"
fi

if grep -q '^ADMIN_PASSWORD=$' "${env_file}"; then
  generated_admin_password="$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=\n')"
  replace_setting "ADMIN_PASSWORD" "${generated_admin_password}"
  password_was_generated=true
else
  password_was_generated=false
fi

replace_setting "HOST" "0.0.0.0"
replace_setting "PORT" "8080"
replace_setting "DEBUG" "false"
replace_setting "COOKIE_SECURE" "true"

mkdir -p data
chmod 700 data

docker compose up -d --build

echo "Waiting for EnAuth to become healthy..."
for attempt in {1..30}; do
  if curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null; then
    echo "EnAuth is running on port 8080."
    if [[ "${password_was_generated}" == true ]]; then
      echo "A random admin password was saved in ${env_file}. View it with: sudo grep '^ADMIN_PASSWORD=' .env"
    fi
    echo "Put an HTTPS reverse proxy in front of port 8080 before exposing EnAuth publicly."
    exit 0
  fi
  sleep 2
done

echo "EnAuth did not become healthy. Inspect it with: docker compose logs --tail=100" >&2
exit 1
