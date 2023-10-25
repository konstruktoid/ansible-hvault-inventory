#!/bin/sh
set -eux

VAULT_PLUGIN_DIRECTORY="/etc/vault.d/plugins"
PASSWORD_GEN_VERSION="0.1.7"
PASSWORD_GEN_FILENAME="vault-secrets-gen_${PASSWORD_GEN_VERSION}_linux_amd64.zip"
PASSWORD_GEN_CHECKSUM="fadb56b9395689fdcffe002abf64df73a66130614efe09627601b129b891ca76"

apt-get update
apt-get --assume-yes upgrade
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

wget "https://github.com/sethvargo/vault-secrets-gen/releases/download/v${PASSWORD_GEN_VERSION}/${PASSWORD_GEN_FILENAME}"

if ! [ "$(sha256sum ${PASSWORD_GEN_FILENAME} | awk '{print $1}')" = "${PASSWORD_GEN_CHECKSUM}" ]; then
  echo "Checksum mismatch. Exiting."
  exit 1
fi

unzip "${PASSWORD_GEN_FILENAME}"

mv -v "vault-secrets-gen_v${PASSWORD_GEN_VERSION}" "${VAULT_PLUGIN_DIRECTORY}/vault-secrets-gen"

setcap cap_ipc_lock=+ep "${VAULT_PLUGIN_DIRECTORY}/vault-secrets-gen"

rm -v "${PASSWORD_GEN_FILENAME}"

echo "vault server -dev -dev-plugin-dir=\"${VAULT_PLUGIN_DIRECTORY}\" --dev-listen-address=$(hostname -I | awk '{print $2}') &> /tmp/vault.log &"
