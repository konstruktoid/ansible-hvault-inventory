#!/bin/sh
set -eux

apt-get update
apt-get --assume-yes upgrade
apt-get --assume-yes install curl jq libcurl4-openssl-dev libssl-dev \
  python3-pip sshpass unzip

python3 -m pip install -U ansible hvac pip pycurl

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
