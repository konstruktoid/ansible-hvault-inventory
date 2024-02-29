# Dynamic Ansible inventory using HashiCorp Vault SSH OTP and local password rotation

`hvault_inventory.py` is a [Ansible](https://www.ansible.com/) [dynamic inventory](https://docs.ansible.com/ansible/latest/user_guide/intro_dynamic_inventory.html)
script that supports a basic K/V setup (`hostname`:`ip`) but also supports
[Vault One-Time SSH Password](https://learn.hashicorp.com/tutorials/vault/ssh-otp)
functionality and the [Vault Password Generator](https://github.com/sethvargo/vault-secrets-gen)
plugin for local password rotation.

## Documentation

In [part one](./ssh_otp.md) HashiCorp Vault and the inventory script is used to
set up OTP SSH authentication.

In addition to SSH OTP, instructions on how to rotate local user passwords are
available in [part 2](./random_password.md).

In [part 3](./ssh_certificates.md) [signed SSH Certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates) are added to the inventory.

## Usage

```console
Dynamic HashiCorp Vault inventory.

This script generates an inventory of hosts from HashiCorp Vault
and outputs it in JSON format for use with Ansible.

Usage:
    python hvault_inventory.py [-h] [-l] [-m MOUNT] [-a ANSIBLE_HOSTS] [-u USER_KEYS]

Options:
    -h, --help              Show the help message and exit.
    -l, --list              Print the inventory.
    -m MOUNT, --mount MOUNT
                            KV backend mount path (default: secret).
    -a ANSIBLE_HOSTS, --ansible-hosts ANSIBLE_HOSTS
                            K/V path to the Ansible hosts (default: ansible-hosts).
    -u USER_KEYS, --user-keys USER_KEYS
                            K/V path to user public keys (default: user-keys).
```

### Environment variables

`VAULT_MOUNT` which is the KV backend mount path with default "secret".

`USER` sets the `ansible_user` variable, if `ansible_user` is not set.

`VAULT_ADDR` and `VAULT_TOKEN` are the Vault server address and Vault token.

### Examples

#### K/V

With default `secret/ansible-hosts`:

```sh
$ ansible-inventory -i hvault_inventory.py --list --yaml
all:
  children:
    vault_hosts:
      hosts:
        server01:
          ansible_host: 192.168.56.41
          ansible_user: vagrant
        server02:
          ansible_host: 192.168.56.42
          ansible_user: vagrant
```

Using environment variables:

```sh
$ VAULT_MOUNT=secret VAULT_SECRET=ansible-hosts ansible-inventory -i hvault_inventory.py --list --yaml
all:
  children:
    vault_hosts:
      hosts:
        server01:
          ansible_host: 192.168.56.41
          ansible_user: vagrant
        server02:
          ansible_host: 192.168.56.42
          ansible_user: vagrant
```

Note that `ansible_user` is set using the `USER` environment variable if
present and `ansible_user` has not been configured manually.

_A path with at least one `hostname:ip` K/V need to
exist since the other options will use this to retrive host information and
build upon it._

#### One-Time SSH Passwords

```sh
$ ansible-inventory -i hvault_inventory.py --list --yaml
all:
  children:
    ungrouped: {}
    vault_hosts:
      hosts:
        server01:
          ansible_host: 192.168.56.41
          ansible_password: 681ddbeb-823b-a10a-4b48-b3e0577ddcdb
          ansible_port: 22
          ansible_user: vagrant
        server02:
          ansible_host: 192.168.56.42
          ansible_password: 06fefcbc-941d-592f-f946-26da0e962d34
          ansible_port: 22
          ansible_user: vagrant
```

#### One-Time SSH Passwords and generated local passwords

```sh
$ ansible-inventory -i hvault_inventory.py --list --yaml
all:
  children:
    ungrouped: {}
    vault_hosts:
      hosts:
        server01:
          ansible_become_password: sprain-doorpost-stylus-decent-strangely
          ansible_host: 192.168.56.41
          ansible_password: 3e927f12-90db-d20f-36c9-33b64e8224d7
          ansible_port: 22
          ansible_user: vagrant
        server02:
          ansible_become_password: pastrami-bullpen-recast-shallot-tinsmith
          ansible_host: 192.168.56.42
          ansible_password: a3cc1375-cd26-51ff-21d2-de4ffff4c2e3
          ansible_port: 22
          ansible_user: vagrant
```

#### SSH certificates

```sh
all:
  children:
    vault_hosts:
      hosts:
        server01:
          ansible_host: 192.168.56.41
          ansible_ssh_private_key_file: /home/vagrant/.ssh/ansible_vagrant_cert.pub
          ansible_user: vagrant
        server02:
          ansible_host: 192.168.56.42
          ansible_ssh_private_key_file: /home/vagrant/.ssh/ansible_vagrant_cert.pub
          ansible_user: vagrant
```

## Scripts and policies

Password rotation and SSH helper scripts are available in the [./scripts](./scripts/)
directory.

Vault policies are available in the [./vault_policies](./vault_policies/)
directory.

### Links

[Ansible dynamic inventory](https://docs.ansible.com/ansible/latest/user_guide/intro_dynamic_inventory.html)

[HashiCorp Vault API client](https://github.com/hvac/hvac)

[HashiCorp Vault](https://www.hashicorp.com/products/vault)

[Vault KV Secrets Engine](https://www.vaultproject.io/docs/secrets/kv)

[Vault One-Time SSH Password](https://learn.hashicorp.com/tutorials/vault/ssh-otp)

[Signed SSH Certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)

[scarolan/painless-password-rotation](https://github.com/scarolan/painless-password-rotation)

[sethvargo/vault-secrets-gen](https://github.com/sethvargo/vault-secrets-gen)

[vault-ssh-helper](https://github.com/hashicorp/vault-ssh-helper)
