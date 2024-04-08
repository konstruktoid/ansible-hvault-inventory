#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0

"""HashiCorp Vault dynamic inventory for Ansible.

This script provides a dynamic inventory for Ansible using HashiCorp Vault as
the backend.

Usage:
------
python hvault_inventory.py [-l] [-a ANSIBLE_HOSTS] [-c CERT_PATH] [-m MOUNT] [-u USER_KEYS]

Options:
--------
-l, --list              Print the inventory.
-a, --ansible-hosts     K/V path to the Ansible hosts (default: ansible-hosts).
-c, --cert-path         Path to the SSH certificate file (default: ~/.ssh/ansible_{ANSIBLE_USER}_cert.pub).
-m, --mount             KV backend mount path (default: secret).
-u, --user-keys         K/V path to user public keys (default: user-keys).

Example:
-------
python3 hvault_inventory.py --list

This will print the generated inventory JSON.

Version: 0.1.1
"""

import argparse
import base64
import configparser
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

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

__version__ = "0.1.1"

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
    "-a",
    "--ansible-hosts",
    help="K/V path to the Ansible hosts, default: ansible-hosts",
)

parser.add_argument(
    "-c",
    "--cert-path",
    help="Path to the SSH certificate file, default: ~/.ssh/ansible_{ANSIBLE_USER}_cert.pub",
)

parser.add_argument(
    "-m",
    "--mount",
    help="KV backend mount path, default: secret",
)

parser.add_argument(
    "-u",
    "--user-keys",
    help="K/V path to user public keys, default: user-keys",
)

args = parser.parse_args()

# Function to read configuration from ansible.cfg
def read_config_file(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    try:
        ansible_hosts = config.get("hvault_inventory", "kv_secret_name")
    except configparser.NoOptionError:
        ansible_hosts = None

    try:
        mount = config.get("hvault_inventory", "kv_mount")
    except configparser.NoOptionError:
        mount = None

    try:
        vault_address = config.get("hvault_inventory", "vault_address")
    except configparser.NoOptionError:
        vault_address = None

    try:
        vault_token = config.get("hvault_inventory", "vault_token")
    except configparser.NoOptionError:
        vault_token = None

    try:
        vault_skip_verify = config.getboolean("hvault_inventory", "vault_skip_verify")
    except configparser.NoOptionError:
        vault_skip_verify = False

    return ansible_hosts, mount, vault_address, vault_token, vault_skip_verify

# Check if ansible.cfg exists and read configuration
ansible_cfg = "ansible.cfg"
ansible_hosts = "ansible-hosts"
mount = "secret"
vault_address = os.environ.get("VAULT_ADDR")
vault_token = os.environ.get("VAULT_TOKEN")
vault_skip_verify = False

if ansible_cfg and os.path.exists(ansible_cfg):
    ansible_hosts, mount, vault_address, vault_token, vault_skip_verify = read_config_file(ansible_cfg)

    if vault_address is None:
        vault_address = os.environ.get("VAULT_ADDR")
    if vault_token is None:
        vault_token = os.environ.get("VAULT_TOKEN")

try:
    client_args = {
        "url": vault_address,
        "token": vault_token
    }

    if vault_skip_verify:
        client_args["verify"] = False

    client = hvac.Client(**client_args)

except KeyError as error:
    print("Input " + str(error) + " is missing.", file=sys.stderr)
    sys.exit(1)

if not client.is_authenticated():
    print("Client is not authenticated.")
    sys.exit(1)

if "VAULT_MOUNT" in os.environ:
    mount = os.environ["VAULT_MOUNT"]

user_keys = args.user_keys if args.user_keys else "user-keys"

def get_ssh_certificate_validity_dates(cert_path: str) -> bool:
    """Get the validity dates of an SSH certificate and check if it is still valid.

    Args:
    ----
        cert_path (str): The path to the SSH certificate file.

    Returns:
    -------
        bool: True if the certificate is still valid, False otherwise.

    """
    result = subprocess.run(
        ["/usr/bin/ssh-keygen", "-L", "-f", cert_path],
        capture_output=True,
        text=True,
        check=False,
        shell=False,  # noqa: S603
    )

    is_valid = False
    for line in result.stdout.split("\n"):
        if "Valid:" in line:
            valid_to = line.split(" ")[-1]

            date_format = "%Y-%m-%dT%H:%M:%S"
            date = datetime.strptime(valid_to, date_format).replace(tzinfo=timezone.utc)
            decreased_date = date - timedelta(minutes=5)
            now = datetime.now(tz=timezone.utc)
            is_valid = now < decreased_date
    return is_valid


try:
    hosts_read_response = client.secrets.kv.v2.read_secret_version(
        mount_point=mount,
        path=ansible_hosts,
        raise_on_deleted_version=True,
    )
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

    postfields = urlencode(post_data)
    buffer = BytesIO()

    otp = pycurl.Curl()
    otp.setopt(otp.URL, os.environ["VAULT_ADDR"] + "/v1/ssh/creds/otp_key_role")
    otp.setopt(otp.WRITEFUNCTION, buffer.write)
    otp.setopt(otp.POSTFIELDS, postfields)
    otp.setopt(
        otp.HTTPHEADER,
        ["X-Vault-Request: true", "X-Vault-Token:" + vault_token],
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

    try:
        if not ANSIBLE_USER:
            try:
                if os.environ["USER"]:
                    ANSIBLE_USER = os.environ["USER"]
            except KeyError:
                pass

        user_password_read_response = client.secrets.kv.v2.read_secret_version(
            mount_point="systemcreds",
            path="linux/" + name + "/" + ANSIBLE_USER + "_creds",
            raise_on_deleted_version=True,
        )

        for username in user_password_read_response["data"]["data"]:
            if username == ANSIBLE_USER:
                ANSIBLE_BECOME_PASSWORD = user_password_read_response["data"]["data"][
                    username
                ]
    except hvac.exceptions.InvalidPath:
        pass
    except TypeError:
        pass
    except hvac.exceptions.Forbidden:
        pass

    ssh_cert_path = (
        args.cert_path
        if args.cert_path
        else Path.home() / ".ssh" / f"ansible_{ANSIBLE_USER}_cert.pub"
    )
    vault_cert_path = True
    valid_ssh_cert = (
        get_ssh_certificate_validity_dates(ssh_cert_path)
        if ssh_cert_path.exists()
        else False
    )

    if not ssh_cert_path.exists() or not valid_ssh_cert:
        try:
            user_keys_read_response = client.secrets.kv.v2.read_secret_version(
                mount_point=mount,
                path=user_keys,
                raise_on_deleted_version=True,
            )
        except hvac.exceptions.InvalidPath:
            vault_cert_path = False
        except TypeError:
            pass
        except hvac.exceptions.Forbidden:
            pass

        if vault_cert_path:
            for user in user_keys_read_response["data"]["data"]:
                if user == ANSIBLE_USER:
                    public_key_base64 = user_keys_read_response["data"]["data"][user]
                    public_key = base64.b64decode(public_key_base64).decode("utf-8")

                    post_data = {"public_key": public_key}
                    postfields = urlencode(post_data)
                    buffer = BytesIO()

                    ssh_signer = pycurl.Curl()
                    ssh_signer.setopt(
                        ssh_signer.URL,
                        os.environ["VAULT_ADDR"]
                        + "/v1/ssh-client-signer/sign/ssh-certs",
                    )
                    ssh_signer.setopt(ssh_signer.WRITEFUNCTION, buffer.write)
                    ssh_signer.setopt(
                        ssh_signer.HTTPHEADER,
                        [
                            "X-Vault-Request: true",
                            "X-Vault-Token:" + os.environ["VAULT_TOKEN"],
                        ],
                    )
                    ssh_signer.setopt(ssh_signer.POSTFIELDS, postfields)
                    ssh_signer.perform()
                    ssh_signer.close()

                    ssh_signer_response = json.loads(buffer.getvalue().decode("utf-8"))
                    ssh_cert = ssh_signer_response["data"]["signed_key"]
                    ssh_cert = ssh_cert.replace("\n", "")
                    ssh_cert_type = public_key.split(" ")[0]

                    with Path(ssh_cert_path).open("w") as f:
                        f.write(ssh_cert)
                        f.close()

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
    if vault_cert_path and ssh_cert_path.exists() and valid_ssh_cert:
        inventory["_meta"]["hostvars"][name]["ansible_ssh_private_key_file"] = str(
            ssh_cert_path,
        )

if args.list:
    print(json.dumps(inventory, sort_keys=True, indent=2))
else:
    print(json.dumps(inventory, sort_keys=True))