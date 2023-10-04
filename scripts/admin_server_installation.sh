#!/bin/sh
set -eux

apt-get update
apt-get --assume-yes upgrade
apt-get --assume-yes install curl jq libcurl4-openssl-dev libssl-dev \
  python3-pip sshpass unzip

python3 -m pip install -U ansible hvac pip pycurl

curl -fsSL https://apt.releases.hashicorp.com/gpg |\
  tee /etc/apt/trusted.gpg.d/hashicorp.asc

apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
apt-get update
apt-get --assume-yes install vault
