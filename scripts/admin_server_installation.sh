#!/bin/sh
set -eux

apt-get update
apt-get -y install ansible curl jq libcurl4-openssl-dev libssl-dev \
  python3-pip sshpass unzip

pip3 install hvac pycurl

curl -fsSL https://apt.releases.hashicorp.com/gpg |\
  tee /etc/apt/trusted.gpg.d/hashicorp.asc

apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
apt-get update
apt-get -y install vault
