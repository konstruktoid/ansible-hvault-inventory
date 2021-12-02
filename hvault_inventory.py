#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0
"""
Populate a Ansible inventory with information from HashiCorp Vault and
use SSH OTP for host access.
"""
import argparse
import os
import sys
from io import BytesIO
import hvac
import pycurl

try:
    import json
except ImportError:
    import simplejson as json

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

__version__ = "0.0.1"

inventory = {}
inventory["vault_hosts"] = []
inventory["_meta"] = {}
inventory["_meta"]["hostvars"] = {}

if not os.environ["VAULT_ADDR"]:
    print("VAULT_ADDR environment variable is empty.")
    sys.exit(1)

if not os.environ["VAULT_TOKEN"]:
    print("VAULT_TOKEN environment variable is empty.")
    sys.exit(1)

client = hvac.Client(
    url=os.environ["VAULT_ADDR"],
    token=os.environ["VAULT_TOKEN"],
)

parser = argparse.ArgumentParser(
    description="HashiCorp Vault inventory and SSH OTP host access.",
    epilog="version: " + __version__,
)

parser.add_argument(
    "-l",
    "--list",
    help="print the inventory",
    action="store_true",
)

args = parser.parse_args()

if not client.is_authenticated():
    print("Client is not authenticated.")
    sys.exit(1)

try:
    read_response = client.secrets.kv.read_secret_version(path="ansible-hosts")
except hvac.exceptions.InvalidPath as exception_string:
    print("InvalidPath Exception: ", str(exception_string), file=sys.stderr)
    sys.exit(1)


for host in read_response["data"]["data"]:
    name = host
    ansible_host = read_response["data"]["data"][host]
    ANSIBLE_USER = None
    ANSIBLE_PASSWORD = None
    ANSIBLE_PORT = None

    inventory["vault_hosts"].append(name)
    inventory["_meta"]["hostvars"][name] = {}

    post_data = {"ip": ansible_host}
    postfields = urlencode(post_data)
    buffer = BytesIO()

    c = pycurl.Curl()
    c.setopt(c.URL, os.environ["VAULT_ADDR"] + "/v1/ssh/creds/otp_key_role")
    c.setopt(c.WRITEFUNCTION, buffer.write)
    c.setopt(c.POSTFIELDS, postfields)
    c.setopt(
        c.HTTPHEADER,
        ["X-Vault-Request: true", "X-Vault-Token:" + os.environ["VAULT_TOKEN"]],
    )
    c.perform()
    c.close()

    ssh_creds_response = json.loads(buffer.getvalue().decode("utf-8"))

    try:
        if ssh_creds_response["data"]["username"]:
            ANSIBLE_USER = ssh_creds_response["data"]["username"]
        if ssh_creds_response["data"]["key"]:
            ANSIBLE_PASSWORD = ssh_creds_response["data"]["key"]
        if ssh_creds_response["data"]["port"]:
            ANSIBLE_PORT = ssh_creds_response["data"]["port"]
    except KeyError:
        pass

    if ansible_host:
        inventory["_meta"]["hostvars"][name]["ansible_host"] = ansible_host
    if ANSIBLE_USER:
        inventory["_meta"]["hostvars"][name]["ansible_user"] = ANSIBLE_USER
    if ANSIBLE_PASSWORD:
        inventory["_meta"]["hostvars"][name]["ansible_password"] = ANSIBLE_PASSWORD
    if ANSIBLE_PORT:
        inventory["_meta"]["hostvars"][name]["ansible_port"] = ANSIBLE_PORT

if args.list:
    print(json.dumps(inventory, sort_keys=True, indent=2))
else:
    print(json.dumps(inventory, sort_keys=True))
