# Dynamic Ansible inventory using HashiCorp Vault

`hvault_inventory.py` is a [Ansible](https://www.ansible.com/) [dynamic inventory](https://docs.ansible.com/ansible/latest/user_guide/intro_dynamic_inventory.html)
script that supports a basic K/V setup (`hostname:ip`) but also supports
[Vault One-Time SSH Password](https://learn.hashicorp.com/tutorials/vault/ssh-otp)
functionality, the [Vault Password Generator](https://github.com/sethvargo/vault-secrets-gen)
plugin for local password rotation and [signed SSH Certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates).

## Documentation

In [part one](./ssh_otp.md) HashiCorp Vault and the inventory script is used to
set up OTP SSH authentication.

In addition to SSH OTP, instructions on how to rotate local user passwords are
available in [part two](./random_password.md).

In [part three](./ssh_certificates.md) signed SSH Certificates are added to the inventory.

## Usage

```console
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
```

### Environment variables

`USER` sets the `ansible_user` variable, if `ansible_user` is not set.

`VAULT_MOUNT` which is the KV backend mount path with default "secret".

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
$ ansible-inventory -i hvault_inventory.py --list --yaml
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

#### Multiple authentication methods

In this examples we'll be using both the `keyboard-interactive` and `publickey` authentication methods,
which will require the user to enter a password and then complete public key authentication.
See [AuthenticationMethods](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html) for the details.

On `server01` and `server02` add the following line to `/etc/ssh/sshd_config.d/99-ssh-auth.conf` and restart the SSH server:

```sh
~$ echo "AuthenticationMethod keyboard-interactive,publickey" | sudo tee /etc/ssh/sshd_config.d/99-ssh-auth.conf
```

On the `admin` machine:

```sh
~$ ssh-add -l
256 SHA256:LLshRz4/FN4UbLjsW+DHXJ4wH6UuVuFrXS0pQ15PQJw vagrant (ED25519)
~$ ansible-inventory -i /vagrant/hvault_inventory.py --list --yaml
all:
  children:
    vault_hosts:
      hosts:
        server01:
          ansible_become_password: scallion-paternal-stamp-produce-fiftieth
          ansible_host: 192.168.56.41
          ansible_password: df9a0219-7393-886a-4375-ae40f846b786
          ansible_port: 22
          ansible_ssh_private_key_file: /home/vagrant/.ssh/ansible_vagrant_cert.pub
          ansible_user: vagrant
        server02:
          ansible_become_password: clavicle-rebate-wick-tall-trespass
          ansible_host: 192.168.56.42
          ansible_password: c1f187d6-f817-f2ca-1ba6-e560da7e42db
          ansible_port: 22
          ansible_ssh_private_key_file: /home/vagrant/.ssh/ansible_vagrant_cert.pub
          ansible_user: vagrant
~$ ssh -v -i /home/vagrant/.ssh/ansible_vagrant_cert.pub 192.168.56.41
[...]
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: keyboard-interactive
debug1: Next authentication method: keyboard-interactive
(vagrant@192.168.56.41) Password: # df9a0219-7393-886a-4375-ae40f846b786
Authenticated using "keyboard-interactive" with partial success.
debug1: Authentications that can continue: publickey
debug1: Next authentication method: publickey
debug1: Offering public key: vagrant ED25519 SHA256:LLshRz4/FN4UbLjsW+DHXJ4wH6UuVuFrXS0pQ15PQJw agent
debug1: Authentications that can continue: publickey
debug1: Offering public key: /home/vagrant/.ssh/ansible_vagrant_cert.pub ED25519-CERT SHA256:LLshRz4/FN4UbLjsW+DHXJ4wH6UuVuFrXS0pQ15PQJw explicit
debug1: Server accepts key: /home/vagrant/.ssh/ansible_vagrant_cert.pub ED25519-CERT SHA256:LLshRz4/FN4UbLjsW+DHXJ4wH6UuVuFrXS0pQ15PQJw explicit
Authenticated to 192.168.56.41 ([192.168.56.41]:22) using "publickey".
[...]
vagrant@server01:~$ sudo -u root -i
[sudo] password for vagrant: # scallion-paternal-stamp-produce-fiftieth
root@server01:~#
```

Running the test playbook using multiple authentication methods:

```sh
~$ ansible-playbook -i /vagrant/hvault_inventory.py /vagrant/playbook.yml

PLAY [Test Hashicorp Vault dynamic inventory] ***************************************************************************************************************************************

TASK [Get ssh host keys from vault_hosts group] *************************************************************************************************************************************
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
ok: [server02 -> localhost] => (item=server01)
ok: [server01 -> localhost] => (item=server01)
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
ok: [server02 -> localhost] => (item=server02)
ok: [server01 -> localhost] => (item=server02)

TASK [Print ansible_password] *******************************************************************************************************************************************************
ok: [server01] => {
    "msg": "79a1c335-c2f3-aa55-d13d-29e99d60aaa9"
}
ok: [server02] => {
    "msg": "f53bb2a7-51d6-f1cc-bf7d-73c6660b9071"
}

TASK [Print ansible_become_password] ************************************************************************************************************************************************
ok: [server01] => {
    "msg": "scallion-paternal-stamp-produce-fiftieth"
}
ok: [server02] => {
    "msg": "clavicle-rebate-wick-tall-trespass"
}

TASK [Print ansible_ssh_private_key_file] *******************************************************************************************************************************************
ok: [server01] => {
    "msg": "/home/vagrant/.ssh/ansible_vagrant_cert.pub"
}
ok: [server02] => {
    "msg": "/home/vagrant/.ssh/ansible_vagrant_cert.pub"
}

TASK [Stat vault-ssh.log] ***********************************************************************************************************************************************************
ok: [server02]
ok: [server01]

TASK [Grep authentication methods] **************************************************************************************************************************************************
ok: [server02]
ok: [server01]

TASK [Grep authentication string from /var/log/vault-ssh.log] ***********************************************************************************************************************
ok: [server02]
ok: [server01]

TASK [Grep keyboard-interactive from /var/log/auth.log] *****************************************************************************************************************************
ok: [server02]
ok: [server01]

TASK [Grep keyboard-interactive from /var/log/auth.log] *****************************************************************************************************************************
ok: [server02]
ok: [server01]

TASK [Print authentication methods] *************************************************************************************************************************************************
ok: [server01] => {
    "msg": "authenticationmethods keyboard-interactive,publickey"
}
ok: [server02] => {
    "msg": "authenticationmethods publickey,keyboard-interactive"
}

TASK [Print authentication string] **************************************************************************************************************************************************
ok: [server01] => {
    "msg": "2024/03/01 16:07:46 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2024/03/01 16:07:46 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [Print keyboard-interactive] ***************************************************************************************************************************************************
ok: [server01] => {
    "msg": "Mar  1 14:11:58 ubuntu-jammy sshd[14636]: Accepted keyboard-interactive/pam for vagrant from 10.0.2.2 port 50680 ssh2"
}
ok: [server02] => {
    "msg": "Mar  1 16:07:46 ubuntu-jammy sshd[16656]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.39 port 44308 ssh2"
}

TASK [Print cert serials] ***********************************************************************************************************************************************************
ok: [server01] => {
    "msg": "Mar 01 16:07:46 server01 sshd[16712]: Accepted publickey for vagrant from 192.168.56.39 port 33784 ssh2: ED25519-CERT SHA256:LLshRz4/FN4UbLjsW+DHXJ4wH6UuVuFrXS0pQ15PQJw ID vault-userpass-vagrant-2cbb21473e3f14de146cb8ec5be0c75c9e301fa52e56e16b5d2d29435e4f409c (serial 1987366443279549857) CA RSA SHA256:DYs6lCx1o/l47JIHUW1jImAILUjBHgkbKOZpFrbBHNI"
}
ok: [server02] => {
    "msg": "Mar 01 15:40:11 server02 sshd[15620]: Accepted publickey for vagrant from 192.168.56.39 port 33162 ssh2: ED25519-CERT SHA256:LLshRz4/FN4UbLjsW+DHXJ4wH6UuVuFrXS0pQ15PQJw ID vault-userpass-vagrant-2cbb21473e3f14de146cb8ec5be0c75c9e301fa52e56e16b5d2d29435e4f409c (serial 7443483942863346275) CA RSA SHA256:DYs6lCx1o/l47JIHUW1jImAILUjBHgkbKOZpFrbBHNI"
}

PLAY RECAP **************************************************************************************************************************************************************************
server01                   : ok=13   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
server02                   : ok=13   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

## Scripts and policies

Password rotation and SSH helper scripts are available in the [./scripts](./scripts/)
directory.

Vault policies are available in the [./vault_policies](./vault_policies/)
directory.

### Links

[Ansible dynamic inventory](https://docs.ansible.com/ansible/latest/user_guide/intro_dynamic_inventory.html)

[KV Secrets Engine](https://www.vaultproject.io/docs/secrets/kv)

[scarolan/painless-password-rotation](https://github.com/scarolan/painless-password-rotation)

[sethvargo/vault-secrets-gen](https://github.com/sethvargo/vault-secrets-gen)

[Signed SSH Certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)

[SSH secrets engine: One-time SSH password](https://learn.hashicorp.com/tutorials/vault/ssh-otp)

[Vault API client](https://github.com/hvac/hvac)

[vault-ssh-helper](https://github.com/hashicorp/vault-ssh-helper)
