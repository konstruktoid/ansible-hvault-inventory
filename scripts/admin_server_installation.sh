#!/bin/sh
set -eux

apt-get update
apt-get --assume-yes upgrade
apt-get --assume-yes install curl jq libcurl4-openssl-dev libssl-dev \
  python3-pip sshpass unzip

python3 -m pip install -U ansible hvac pip pycurl
