#!/bin/sh

set -eux

VERSION="0.2.1"
SHASUM="fe26f62e5822bdf66ea4bf874d1a535ffca19af07a27ff3bcd7e344bc1af39fe"
FILENAME="vault-ssh-helper_${VERSION}_linux_amd64.zip"

VAULT_SERVER="192.168.56.40"

apt-get update
apt-get -y install unzip wget

wget "https://releases.hashicorp.com/vault-ssh-helper/${VERSION}/${FILENAME}"

if ! [ "$(sha256sum ${FILENAME} | awk '{print $1}')" = "${SHASUM}" ]; then
  echo "Checksum mismatch. Exiting."
  exit 1
fi

unzip -q "vault-ssh-helper_${VERSION}_linux_amd64.zip" -d /usr/local/bin

chmod 0755 /usr/local/bin/vault-ssh-helper
chown root:root /usr/local/bin/vault-ssh-helper
mkdir /etc/vault-ssh-helper.d/

tee /etc/vault-ssh-helper.d/config.hcl <<EOF
vault_addr = "http://${VAULT_SERVER}:8200"
tls_skip_verify = false
ssh_mount_point = "ssh"
allowed_roles = "*"
EOF

chmod 0644 /etc/vault-ssh-helper.d/config.hcl
chown root:root /etc/vault-ssh-helper.d/config.hcl

rm -v "vault-ssh-helper_${VERSION}_linux_amd64.zip"
