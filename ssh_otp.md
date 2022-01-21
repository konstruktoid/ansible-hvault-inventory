# Using HashiCorp Vault as a dynamic Ansible inventory and authentication service, part 1

## Introduction

This is a example on how to use [HashiCorp Vault](https://www.hashicorp.com/products/vault)
as a dynamic [Ansible](https://www.ansible.com/) inventory, and use the
[One-Time SSH Password](https://learn.hashicorp.com/tutorials/vault/ssh-otp)
functionality to create a one-time password every time Ansible makes a SSH
connection into a managed host.

In addition to SSH OTP, instructions on how to rotate local user passwords are
available in [part 2](./random_password.md).

If you don't want to spend the time to
[install Vault](https://learn.hashicorp.com/tutorials/vault/getting-started-install),
the [vault-ssh-helper](https://github.com/hashicorp/vault-ssh-helper) or the
[vault-secrets-gen](https://github.com/sethvargo/vault-secrets-gen)
you can use the available [Vagrantfile](https://www.vagrantup.com/) by running
`vagrant up`.

See [vault_server_installation.sh](./scripts/vault_server_installation.sh) and
[vault_ssh_helper_installation.sh](./scripts/vault_ssh_helper_installation.sh) for
the installation process.

```console
Do not use any of this without testing in a non-operational environment.
```

## The inventory script

[hvault_inventory.py](./hvault_inventory.py) is a Python script that uses the
[HashiCorp Vault API client](https://github.com/hvac/hvac) and [PycURL](http://pycurl.io/)
libraries to communicate with the Vault server and generate a [dynamic inventory](https://docs.ansible.com/ansible/latest/user_guide/intro_dynamic_inventory.html)
for use with Ansible.

`hvault_inventory.py` reads the `secret/ansible-hosts` Vault path to get the
list of managed hosts (`hostname`:`ip`), then uses the IP Addresses to write
`/ssh/creds/otp_key_role` and retrive the created SSH OTP credentials.

For password rotation the `"linux/" + name + "/" + ANSIBLE_USER + "_creds"` path
is used, where `name` is the hostname and `ANSIBLE_USER` is the Ansible user,
setting `ansible_become_password`.

## Vault and host onfiguration

We will use Vagrant and the configured virtul machines, this will create four
servers; `vault` which is the Vault server, `admin` which is server from where
we'll run Ansible and two managed hosts named `server01` and `server02`.

The admin server will have the IP address `192.168.56.39`, Vault server
`192.168.56.40`, and the two hosts will use `192.168.56.41` and `192.168.56.42`.

Make sure to update the addresses if you decide to use another environment.

### Configuration of the Vault server

After the installation of the Vault server, we will use the ["Dev" Server Mode](https://www.vaultproject.io/docs/concepts/dev-server)
just to get started quickly.

On `vault`:

```sh
$ vault server -dev -dev-plugin-dir="/etc/vault.d/plugins" --dev-listen-address=192.168.56.40:8200 &> /tmp/vault.log &
$ grep -Eo '(VAULT_ADDR|Root Token).*' /tmp/vault.log
VAULT_ADDR='http://192.168.56.40:8200'
Root Token: s.xGmLKTqQc4N2dvwgqgYypWZ7
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ export VAULT_TOKEN='s.xGmLKTqQc4N2dvwgqgYypWZ7'
```

#### KV Secrets Engine

Using the [KV Secrets Engine](https://www.vaultproject.io/docs/secrets/kv) we'll
add the names and IP addresses of the two hosts that will be managed by Ansible.

```sh
$ vault kv put secret/ansible-hosts server01=192.168.56.41 server02=192.168.56.42
Key                Value
---                -----
created_time       2021-12-02T20:55:13.307449391Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1
$ vault kv get secret/ansible-hosts
======= Metadata =======
Key                Value
---                -----
created_time       2021-12-02T20:55:13.307449391Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1

====== Data ======
Key         Value
---         -----
server01    192.168.56.41
server02    192.168.56.42
```

With `ansible-inventory -i hvault_inventory.py --list` we will verify that the
script can read the Vault path and build a basic inventory.

`ansible_user`, if not configured, is by default the `USER` environment
variable.

On `admin`:

```sh
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ export VAULT_TOKEN='s.xGmLKTqQc4N2dvwgqgYypWZ7'
$ ansible-inventory -i hvault_inventory.py --list
{
    "_meta": {
        "hostvars": {
            "server01": {
                "ansible_host": "192.168.56.41",
                "ansible_user": "vagrant"
            },
            "server02": {
                "ansible_host": "192.168.56.42",
                "ansible_user": "vagrant"
            }
        }
    },
    "all": {
        "children": [
            "ungrouped",
            "vault_hosts"
        ]
    },
    "vault_hosts": {
        "hosts": [
            "server01",
            "server02"
        ]
    }
}
```

#### SSH Secrets Engine

In addition to using Vault as a basic inventory, we will use the
[SSH Secrets Engine](https://learn.hashicorp.com/tutorials/vault/ssh-otp) to
create one-time passwords for the SSH authentication.

On the Vault server we first mount the secrets engine and then configure the
role.

On `vault`:

```sh
$ vault secrets enable ssh
Success! Enabled the ssh secrets engine at: ssh/
$ vault write ssh/roles/otp_key_role key_type=otp default_user=vagrant cidr_list=192.168.56.0/24
Success! Data written to: ssh/roles/otp_key_role
```

Setting `default_user=vagrant` and `cidr_list=192.168.56.0/24` because Vagrant
and the IP addresses configured.

The [ansible.hcl](./vault_policies/ansible.hcl) policy grants a user the
capabilites to read, create and update both the list of the Ansible managed
hosts and the OTP role.

```sh
$ tee ansible.hcl <<EOF
path "secret/data/ansible-hosts" {
  capabilities = ["read", "create", "update"]
}

path "ssh/*" {
  capabilities = [ "list" ]
}

path "ssh/creds/otp_key_role" {
  capabilities = ["create", "read", "update"]
}
EOF
```

The policy is uploaded to the Vault server using
`vault policy write ansible ansible.hcl`.

After the policy has been uploaded we will enable the `userpass` auth method
which allows users to authenticate with Vault using a username and password
combination.

After `userpass` has been enabled, the user `vagrant` with the password
`HorsePassport` using the `ansible` policy will be created.

```sh
$ vault auth enable userpass
Success! Enabled userpass auth method at: userpass/
$ vault write auth/userpass/users/vagrant password="HorsePassport" policies="ansible"
Success! Data written to: auth/userpass/users/vagrant
```

#### Managed host configuration

After the Vault server has been configured the hosts that should be managed
is next.

The [vault_ssh_helper_installation.sh](./scripts/vault_ssh_helper_installation.sh)
script, which is used on the Vagrant virtual machines, automates the
installation of the [vault-ssh-helper](https://github.com/hashicorp/vault-ssh-helper)
tool.

Below is the generation and verification of the `vault-ssh-helper.d/config.hcl`
configuration file.

```sh
$ sudo tee /etc/vault-ssh-helper.d/config.hcl <<EOF
vault_addr = "http://192.168.56.40:8200"
tls_skip_verify = false
ssh_mount_point = "ssh"
allowed_roles = "*"
EOF
$ vault-ssh-helper -verify-only -dev -config /etc/vault-ssh-helper.d/config.hcl
2021/12/02 22:59:47 ==> WARNING: Dev mode is enabled!
2021/12/02 22:59:47 [INFO] using SSH mount point: ssh
2021/12/02 22:59:47 [INFO] using namespace:
2021/12/02 22:59:47 [INFO] vault-ssh-helper verification successful!
```

`sshd` configuration:

```sh
$ grep -vE '#|^$' /etc/ssh/sshd_config | uniq
Include /etc/ssh/sshd_config.d/*.conf
PasswordAuthentication no
ChallengeResponseAuthentication yes
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
```

`sshd` PAM configuration:

```sh
$ grep -vE '#|^$' /etc/pam.d/sshd
auth requisite pam_exec.so quiet expose_authtok log=/var/log/vault-ssh.log /usr/local/bin/vault-ssh-helper -dev -config=/etc/vault-ssh-helper.d/config.hcl
auth optional pam_unix.so not_set_pass use_first_pass nodelay
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    required     pam_limits.so
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open
@include common-password
```

## Usage

The following is a step-by-step example on a host that is used as a Ansible
management node.

On `admin`:

```sh
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ vault login -method=userpass username=vagrant password=HorsePassport
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                    Value
---                    -----
token                  s.RjgPRwkH91LcfE8AC2T99LHH
token_accessor         jMyeINuhUIoap8lod6TZkBjT
token_duration         768h
token_renewable        true
token_policies         ["ansible" "default"]
identity_policies      []
policies               ["ansible" "default"]
token_meta_username    vagrant
$ export VAULT_TOKEN='s.RjgPRwkH91LcfE8AC2T99LHH'
$ ansible-inventory -i hvault_inventory.py --list
{
    "_meta": {
        "hostvars": {
            "server01": {
                "ansible_host": "192.168.56.41",
                "ansible_password": "31192d73-3315-4bfc-e439-61062cb5b137",
                "ansible_port": 22,
                "ansible_user": "vagrant"
            },
            "server02": {
                "ansible_host": "192.168.56.42",
                "ansible_password": "373fcf9d-f8d8-5efb-c672-436a8eba032f",
                "ansible_port": 22,
                "ansible_user": "vagrant"
            }
        }
    },
    "all": {
        "children": [
            "ungrouped",
            "vault_hosts"
        ]
    },
    "vault_hosts": {
        "hosts": [
            "server01",
            "server02"
        ]
    }
}
$ for repeat in 1 2 3; do ansible-inventory -i hvault_inventory.py --host server01 | jq -r '.ansible_password'; done
8f2854b4-da56-ebf0-e264-d50ca6010fad
d7751c32-b1cf-e1f3-f689-1614eecd55fc
cad1a564-521c-67ff-b885-d00c191e016e
```

A sample [Ansible playbook](./playbook.yml) is used for additional verification
and testing.

```sh
$ ansible-playbook -i hvault_inventory.py playbook.yml

PLAY [all] *********************************************************************

TASK [get ssh host keys from vault_hosts group] ********************************
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
ok: [server02 -> localhost] => (item=server01)
ok: [server01 -> localhost] => (item=server01)
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
ok: [server02 -> localhost] => (item=server02)
ok: [server01 -> localhost] => (item=server02)

TASK [print ansible_password] **************************************************
ok: [server01] => {
    "changed": false,
    "msg": "db295db0-b310-1039-1b3c-9b9115d441ae"
}
ok: [server02] => {
    "changed": false,
    "msg": "c6fea6df-2c5d-b15b-ecff-740343a71e99"
}

TASK [print ansible_become_password] *******************************************
skipping: [server01]
skipping: [server02]

TASK [grep authentication string from /var/log/vault-ssh.log] ******************
ok: [server01]
ok: [server02]

TASK [grep keyboard-interactive from /var/log/auth.log] ************************
ok: [server01]
ok: [server02]

TASK [print authentication string] *********************************************
ok: [server01] => {
    "msg": "2022/01/21 13:29:42 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2022/01/21 13:29:42 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [print keyboard-interactive] **********************************************
ok: [server01] => {
    "msg": "Jan 21 13:29:42 ubuntu-focal sshd[28851]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.40 port 55408 ssh2"
}
ok: [server02] => {
    "msg": "Jan 21 13:29:42 ubuntu-focal sshd[28348]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.40 port 41558 ssh2"
}

PLAY RECAP *********************************************************************
server01                   : ok=6    changed=0    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
server02                   : ok=6    changed=0    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```
