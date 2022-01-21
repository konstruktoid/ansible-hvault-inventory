#!/bin/sh
set -eux

VAULT_PLUGIN_DIRECTORY="/etc/vault.d/plugins"
PASSWORD_GEN_VERSION="0.1.6"
PASSWORD_GEN_FILENAME="vault-secrets-gen_${PASSWORD_GEN_VERSION}_linux_amd64.zip"
PASSWORD_GEN_CHECKSUM="915d22b11cd7cf1cabd6256b184f1f561668ef8b550e49fa257c9587f9dd58ae"

apt-get update
apt-get -y install ansible curl jq libcurl4-openssl-dev libssl-dev \
  python3-pip sshpass unzip

pip3 install hvac pycurl

curl -fsSL https://apt.releases.hashicorp.com/gpg |\
  tee /etc/apt/trusted.gpg.d/hashicorp.asc

apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
apt-get update
apt-get -y install vault

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
