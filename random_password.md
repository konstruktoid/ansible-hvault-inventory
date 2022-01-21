# Using HashiCorp Vault as a dynamic Ansible inventory and authentication service, part 2

In [part one](./ssh_otp.md) HashiCorp Vault and the inventory script was used to
set up OTP SSH authentication.

In this part we'll expand that by adding password rotation to the `ANSIBLE_USER`
account.

```console
Do not use any of this without testing in a non-operational environment.
```

## In summary

- [SSH OTP authentication](./ssh_otp.md)
- Enable a [Password Generator](https://github.com/sethvargo/vault-secrets-gen)
- Configure `sudo` to require passwords
- Rotate the [local user password](https://github.com/scarolan/painless-password-rotation),
  and use it as `ansible_become_password`.

## Vault and host configuration

See [part one](./ssh_otp.md) for steps and details.

### Enable the Password Generator

[vault_server_installation.sh](scripts/vault_server_installation.sh)
is a script that will install Vault and the Password Generator on a host, and
is used by the available Vagrant images.

If you prefer to do it manually, the documentation is available at
[sethvargo/vault-secrets-gen](https://github.com/sethvargo/vault-secrets-gen).

Ensure that the `VAULT_ADDR` and `VAULT_TOKEN` values are set on the Vault server.

```sh
$ grep -Eo '(VAULT_ADDR|Root Token).*' /tmp/vault.log && grep -A2 'plugins are registered' /tmp/vault.log
VAULT_ADDR='http://192.168.56.40:8200'
Root Token: s.dCXFnEIKeZ7xFIq1wBYvXjTc
The following dev plugins are registered in the catalog:
    - vault-secrets-gen

$ export VAULT_ADDR='http://192.168.56.40:8200'
$ export VAULT_TOKEN='s.dCXFnEIKeZ7xFIq1wBYvXjTc'
```

Enable the `vault-secrets-gen` plugin:

```sh
$ export SHA256=$(shasum -a 256 "/etc/vault.d/plugins/vault-secrets-gen" | awk '{print $1}')
$ vault plugin register -sha256="${SHA256}" -command="vault-secrets-gen" secret secrets-gen
Success! Registered plugin: secrets-gen
$ vault secrets enable -path="gen" -plugin-name="secrets-gen" plugin
Success! Enabled the secrets-gen secrets engine at: gen/
```

## Password rotation

_This part is heavily inspired by [scarolan/painless-password-rotation](https://github.com/scarolan/painless-password-rotation)_

Enable [KV Secrets Engine](https://www.vaultproject.io/docs/secrets/kv) with the
`systemcreds/` path  on the Vault server:

```sh
$ vault secrets enable -path="systemcreds" kv
Success! Enabled the kv secrets engine at: systemcreds/
```

Upload the [rotate-linux.hcl](./vault_policies/rotate-linux.hcl) and
[linuxadmin.hcl](vault_policies/linuxadmin.hcl) policies.

```sh
$ vault policy write rotate-linux rotate-linux.hcl
Success! Uploaded policy: rotate-linux
$ vault policy write linuxadmin linuxadmin.hcl
```

Create a authentication token for the `rotate-linux` policy with a 24 hour
lifetime.

```sh
$ vault token create -period 24h -policy rotate-linux
Key                  Value
---                  -----
token                s.2pWWUE9CtMbDEO5tOIt5Qvrx
token_accessor       wK5aqTyXrzEBu941I3zAWjYC
token_duration       24h
token_renewable      true
token_policies       ["default" "rotate-linux"]
identity_policies    []
policies             ["default" "rotate-linux"]
``´

The `token` value should be used as the `VAULT_TOKEN` on the managed servers,
and both `VAULT_ADDR` and `VAULT_TOKEN` should be present in `/etc/environment`
or equivalent.

### User policies

The user `vagrant` with the password `HorsePassport` using the `ansible` and
`linuxadmin` policies should be created or updated.

On `vault`:

```sh
$ vault write auth/userpass/users/vagrant password="HorsePassport" policies="ansible,linuxadmin"
```

Copy [rotate_linux_password.sh](scripts/rotate_linux_password.sh) to the managed
servers and generate a password for the user.

`bash ./rotate_linux_password.sh "$(id -un)"`

Ensure that any `sudo` `NOPASSWD:` tags has been replaced with `PASSWD:` after
a password has been generated and stored in Vault.

On `admin`:

```
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ vault login -method=userpass username=vagrant password=HorsePassport
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                    Value
---                    -----
token                  s.i4n9f5d053jyNsRgNj1W9rPt
token_accessor         Hd59laHlSZyHAmdJiy45k2Cf
token_duration         768h
token_renewable        true
token_policies         ["ansible" "default" "linuxadmin"]
identity_policies      []
policies               ["ansible" "default" "linuxadmin"]
token_meta_username    vagrant
$ export VAULT_TOKEN='s.i4n9f5d053jyNsRgNj1W9rPt'
$ ansible-inventory -i hvault_inventory.py --list
$ ansible-inventory -i hvault_inventory.py --list --yaml
all:
  children:
    ungrouped: {}
    vault_hosts:
      hosts:
        server01:
          ansible_become_password: sprain-doorpost-stylus-decent-strangely
          ansible_host: 192.168.56.41
          ansible_password: ea3ef6ae-285e-26fa-1450-ed7217461d78
          ansible_port: 22
          ansible_user: vagrant
        server02:
          ansible_become_password: pastrami-bullpen-recast-shallot-tinsmith
          ansible_host: 192.168.56.42
          ansible_password: f7502d52-781a-e818-6edb-9ea374dbd032
          ansible_port: 22
          ansible_user: vagrant
$ ansible-playbook -i hvault_inventory.py playbook.yml

PLAY [all] *********************************************************************

TASK [get ssh host keys from vault_hosts group] ********************************
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4
ok: [server01 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server01)
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
ok: [server02 -> localhost] => (item=server02)
ok: [server01 -> localhost] => (item=server02)

TASK [print ansible_password] **************************************************
ok: [server01] => {
    "changed": false,
    "msg": "93480236-d884-5179-2008-01f80a2d6f45"
}
ok: [server02] => {
    "changed": false,
    "msg": "a8d792cd-f3da-b037-f2b1-e18b6734cb76"
}

TASK [print ansible_become_password] *******************************************
ok: [server01] => {
    "changed": false,
    "msg": "sprain-doorpost-stylus-decent-strangely"
}
ok: [server02] => {
    "changed": false,
    "msg": "pastrami-bullpen-recast-shallot-tinsmith"
}

TASK [grep authentication string from /var/log/vault-ssh.log] ******************
ok: [server02]
ok: [server01]

TASK [grep keyboard-interactive from /var/log/auth.log] ************************
ok: [server01]
ok: [server02]

TASK [print authentication string] *********************************************
ok: [server01] => {
    "msg": "2022/01/21 14:09:10 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2022/01/21 14:09:10 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [print keyboard-interactive] **********************************************
ok: [server01] => {
    "msg": "Jan 21 14:09:10 ubuntu-focal sshd[39724]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.40 port 55454 ssh2"
}
ok: [server02] => {
    "msg": "Jan 21 14:09:10 ubuntu-focal sshd[31384]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.40 port 41604 ssh2"
}

PLAY RECAP *********************************************************************
server01                   : ok=7    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
server02                   : ok=7    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
``
