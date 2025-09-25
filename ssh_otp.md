# Using HashiCorp Vault as a dynamic Ansible inventory and authentication service, part 1

## Introduction

This is a example on how to use [HashiCorp Vault](https://www.hashicorp.com/products/vault)
as a dynamic [Ansible](https://www.ansible.com/) inventory, and use the
[One-Time SSH Password](https://learn.hashicorp.com/tutorials/vault/ssh-otp)
functionality to create a one-time password every time Ansible makes a SSH
connection into a managed host.

In addition to SSH OTP, instructions on how to rotate local user passwords are
available in [part two](./random_password.md).

If you don't want to spend the time to
[install Vault](https://learn.hashicorp.com/tutorials/vault/getting-started-install),
the [vault-ssh-helper](https://github.com/hashicorp/vault-ssh-helper)
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
libraries to communicate with the Vault server and generate a [dynamic inventory](https://docs.ansible.com/ansible/latest/inventory_guide/intro_dynamic_inventory.html)
for use with Ansible.

`hvault_inventory.py` reads a Vault path, `secret/ansible-hosts` by default,
to get the list of managed hosts (`hostname:ip`), then uses the IP Addresses
to write `/ssh/creds/otp_key_role` and retrive the created SSH OTP credentials.

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

After the installation of the Vault server, we will use the ["Dev" Server Mode](https://developer.hashicorp.com/vault/docs/concepts/dev-server)
just to get started quickly.

On `vault`:

```sh
$ vault server -dev -dev-plugin-dir="/etc/vault.d/plugins" --dev-listen-address=192.168.56.40:8200 &> /tmp/vault.log &
$ grep -Eo '(VAULT_ADDR|Root Token).*' /tmp/vault.log
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ export VAULT_TOKEN='hvs.vDkyJoiMWV3JuBn9sqd7g307'
```

#### KV Secrets Engine

Using the [KV Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/kv) we'll
add the names and IP addresses of the two hosts that will be managed by Ansible.

On `vault`:

```sh
$ vault kv put -mount=secret ansible-hosts server01=192.168.56.41 server02=192.168.56.42
====== Secret Path ======
secret/data/ansible-hosts

======= Metadata =======
Key                Value
---                -----
created_time       2025-01-30T21:39:07.645839328Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1
$ vault kv get -mount=secret ansible-hosts
====== Secret Path ======
secret/data/ansible-hosts

======= Metadata =======
Key                Value
---                -----
created_time       2025-01-30T21:39:07.645839328Z
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
$ export VAULT_TOKEN='hvs.vDkyJoiMWV3JuBn9sqd7g307'
$ python3 hvault_inventory.py --list
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
  "vault_hosts": [
    "server01",
    "server02"
  ]
}
```

Note that using the root token is [not in any way recommended](https://developer.hashicorp.com/vault/docs/concepts/tokens#root-tokens),
and is used only for testing.

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

Setting `default_user=vagrant` and `cidr_list=192.168.56.0/24` because we're
using the Vagrant environment and the IP addresses configured.

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

On `server01` and `server02`:

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

Ensure that `sshd` is configured with the following settings:

```sh
echo "ChallengeResponseAuthentication yes
UsePAM yes
PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/99-ssh-otp.conf
```

Ensure that the `/etc/pam.d/sshd` file has the following settings:

```sh
#@include common-auth
auth requisite pam_exec.so quiet expose_authtok log=/var/log/vault-ssh.log /usr/local/bin/vault-ssh-helper -dev -config=/etc/vault-ssh-helper.d/config.hcl
auth optional pam_unix.so use_first_pass nodelay
```

Note that with the `-dev` option set `vault-ssh-helper` communicates with Vault
with TLS disabled. This is NOT recommended for production use.

Finally restart the `sshd` service.

## Usage

The following is a step-by-step example on a host that is used as a Ansible
management node.

On `admin`:

```sh
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ unset VAULT_TOKEN
$ vault login -method=userpass username=vagrant password=HorsePassport
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                    Value
---                    -----
token                  hvs.CAESIAOrlcwOteUdSJRK49alyQmBFMGw_dgzn1CZM35gya...
token_accessor         gEcH7AMHezSPnhnpdi9F3sA0
token_duration         768h
token_renewable        true
token_policies         ["ansible" "default"]
identity_policies      []
policies               ["ansible" "default"]
token_meta_username    vagrant

$ export VAULT_TOKEN='hvs.CAESIAOrlcwOteUdSJRK49alyQmBFMGw_dgzn1CZM35gya...
$ ansible-inventory -i hvault_inventory.py --list
{
    "_meta": {
        "hostvars": {
            "server01": {
                "ansible_host": "192.168.56.41",
                "ansible_password": "28c57a0d-5f74-1b34-285f-9305e707941b",
                "ansible_port": 22,
                "ansible_user": "vagrant"
            },
            "server02": {
                "ansible_host": "192.168.56.42",
                "ansible_password": "22697bee-094c-dfd9-9fa5-f454571316fa",
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
b368e271-7ccc-53ea-7eff-537a97a1f2f0
0e4259b4-76dc-f211-5893-3a0e3c54e1e9
f47b81af-4fc5-d186-48e9-59cf2ce2e3d4
```

A sample [Ansible playbook](./playbook.yml) is used for additional verification
and testing.

```sh
$ ansible-playbook -i hvault_inventory.py playbook.yml

PLAY [Test Hashicorp Vault dynamic inventory] ******************************************************

TASK [Get ssh host keys from vault_hosts group] ****************************************************
ok: [server02 -> localhost] => (item=server01)
ok: [server01 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server02)
ok: [server01 -> localhost] => (item=server02)

TASK [Print ansible_password] **********************************************************************
ok: [server01] => {
    "msg": "31f64122-6b1d-9885-ec53-364ecd52616a"
}
ok: [server02] => {
    "msg": "16fa5ee6-337a-5c7d-9a95-49becdbc0248"
}

TASK [Print ansible_become_password] ***************************************************************
skipping: [server01]
skipping: [server02]

TASK [Print ansible_ssh_private_key_file] **********************************************************
skipping: [server01]
skipping: [server02]

TASK [Stat vault-ssh.log] **************************************************************************
ok: [server02]
ok: [server01]

TASK [Grep authentication methods] *****************************************************************
ok: [server02]
ok: [server01]

TASK [Grep authentication string from /var/log/vault-ssh.log] **************************************
ok: [server01]
ok: [server02]

TASK [Grep keyboard-interactive from /var/log/auth.log] ********************************************
ok: [server02]
ok: [server01]

TASK [Grep keyboard-interactive from /var/log/auth.log] ********************************************
skipping: [server01]
skipping: [server02]

TASK [Print authentication methods] ****************************************************************
ok: [server01] => {
    "msg": "authenticationmethods any"
}
ok: [server02] => {
    "msg": "authenticationmethods any"
}

TASK [Print authentication string] ******************************************************************
ok: [server01] => {
    "msg": "2025/01/30 22:17:54 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2025/01/30 22:17:54 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [Print keyboard-interactive] *******************************************************************
ok: [server01] => {
    "msg": "2025-01-30T22:17:54.137334+00:00 vagrant sshd[3186]: Accepted keyboard-interactive/pam...
}
ok: [server02] => {
    "msg": "2025-01-30T22:17:54.083261+00:00 vagrant sshd[3124]: Accepted keyboard-interactive/pam...
}

TASK [Print cert serials] ***************************************************************************
skipping: [server01]
skipping: [server02]
```
