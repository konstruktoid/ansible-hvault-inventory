#!/bin/sh
set -eux

VAULT_PLUGIN_DIRECTORY="/etc/vault.d/plugins"

apt-get update
apt-get --assume-yes install curl unzip

curl -fsSL https://apt.releases.hashicorp.com/gpg |\
  gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

echo "Types: deb
URIs: https://apt.releases.hashicorp.com
Suites: $(lsb_release -cs)
Components: main
Architectures: $(dpkg --print-architecture)
Signed-by: /usr/share/keyrings/hashicorp-archive-keyring.gpg" | tee /etc/apt/sources.list.d/hashicorp.sources

apt-get update
apt-get --assume-yes install vault

if ! grep -q 'plugin_directory' /etc/vault.d/vault.hcl; then
  echo "plugin_directory = ${VAULT_PLUGIN_DIRECTORY}" >> /etc/vault.d/vault.hcl
else
  VAULT_PLUGIN_DIRECTORY="$(grep 'plugin_directory' /etc/vault.d/vault.hcl | awk '{print $NF}')"
fi

if ! [ -d "${VAULT_PLUGIN_DIRECTORY}" ]; then
  mkdir -p "${VAULT_PLUGIN_DIRECTORY}"
fi

echo "vault server -dev -dev-plugin-dir=\"${VAULT_PLUGIN_DIRECTORY}\" --dev-listen-address=$(hostname -I | awk '{print $2}') &> /tmp/vault.log &"
