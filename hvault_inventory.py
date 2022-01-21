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

__version__ = "0.0.2"

inventory = {}
inventory["vault_hosts"] = []
inventory["_meta"] = {}
inventory["_meta"]["hostvars"] = {}

parser = argparse.ArgumentParser(
    description="Dynamic HashiCorp Vault inventory.",
    epilog="version: " + __version__,
)

parser.add_argument(
    "-l",
    "--list",
    help="print the inventory",
    action="store_true",
)

parser.add_argument(
    "-o",
    "--otp-only",
    help="show only SSH OTP information",
    action="store_true",
)

parser.add_argument(
    "-p",
    "--password-only",
    help="show only local password information",
    action="store_true",
)

args = parser.parse_args()

try:
    client = hvac.Client(
        url=os.environ["VAULT_ADDR"],
        token=os.environ["VAULT_TOKEN"],
    )

except KeyError as error:
    print("Environment variable " + str(error) + " is missing.", file=sys.stderr)
    sys.exit(1)

if not client.is_authenticated():
    print("Client is not authenticated.")
    sys.exit(1)

try:
    hosts_read_response = client.secrets.kv.read_secret_version(path="ansible-hosts")
except hvac.exceptions.InvalidPath as exception_string:
    print("InvalidPath Exception: ", str(exception_string), file=sys.stderr)
    sys.exit(1)


for host in hosts_read_response["data"]["data"]:
    name = host
    ansible_host = hosts_read_response["data"]["data"][host]
    ANSIBLE_USER = None
    ANSIBLE_PASSWORD = None
    ANSIBLE_PORT = None
    ANSIBLE_BECOME_PASSWORD = None

    inventory["vault_hosts"].append(name)
    inventory["_meta"]["hostvars"][name] = {}

    post_data = {"ip": ansible_host}

    if not args.password_only:
        postfields = urlencode(post_data)
        buffer = BytesIO()

        otp = pycurl.Curl()
        otp.setopt(otp.URL, os.environ["VAULT_ADDR"] + "/v1/ssh/creds/otp_key_role")
        otp.setopt(otp.WRITEFUNCTION, buffer.write)
        otp.setopt(otp.POSTFIELDS, postfields)
        otp.setopt(
            otp.HTTPHEADER,
            ["X-Vault-Request: true", "X-Vault-Token:" + os.environ["VAULT_TOKEN"]],
        )
        otp.perform()
        otp.close()

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

    if not args.otp_only:
        try:
            if not ANSIBLE_USER:
                try:
                    if os.environ["USER"]:
                        ANSIBLE_USER = os.environ["USER"]
                except KeyError:
                    pass

            user_password_read_response = client.secrets.kv.read_secret_version(
                path="linux/" + name + "/" + ANSIBLE_USER + "_creds",
                mount_point="systemcreds",
            )

            for username in user_password_read_response["data"]["data"]:
                if username == ANSIBLE_USER:
                    ANSIBLE_BECOME_PASSWORD = user_password_read_response["data"][
                        "data"
                    ][username]
        except hvac.exceptions.InvalidPath:
            pass
        except TypeError:
            pass
        except hvac.exceptions.Forbidden:
            pass

    if ansible_host:
        inventory["_meta"]["hostvars"][name]["ansible_host"] = ansible_host
    if ANSIBLE_USER:
        inventory["_meta"]["hostvars"][name]["ansible_user"] = ANSIBLE_USER
    if ANSIBLE_PASSWORD:
        inventory["_meta"]["hostvars"][name]["ansible_password"] = ANSIBLE_PASSWORD
    if ANSIBLE_PORT:
        inventory["_meta"]["hostvars"][name]["ansible_port"] = ANSIBLE_PORT
    if ANSIBLE_BECOME_PASSWORD:
        inventory["_meta"]["hostvars"][name][
            "ansible_become_password"
        ] = ANSIBLE_BECOME_PASSWORD

if args.list:
    print(json.dumps(inventory, sort_keys=True, indent=2))
else:
    print(json.dumps(inventory, sort_keys=True))
