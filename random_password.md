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
- Configure `sudo` to require passwords
- Rotate the [local user password](https://github.com/scarolan/painless-password-rotation),
  and use it as `ansible_become_password`.

## Vault and host configuration

See [part one](./ssh_otp.md) for steps and details.

## Password rotation

_This part is heavily inspired by [scarolan/painless-password-rotation](https://github.com/scarolan/painless-password-rotation)_

Enable [KV Secrets Engine](https://www.vaultproject.io/docs/secrets/kv) with the
`systemcreds/` path on the Vault server:

```sh
$ vault secrets enable -version=2 -path="systemcreds" kv
Success! Enabled the kv secrets engine at: systemcreds/
```

Upload the [rotate-linux.hcl](./vault_policies/rotate-linux.hcl) and
[linuxadmin.hcl](vault_policies/linuxadmin.hcl) policies.

```sh
$ vault policy write rotate-linux rotate-linux.hcl
Success! Uploaded policy: rotate-linux
$ vault policy write linuxadmin linuxadmin.hcl
Success! Uploaded policy: linuxadmin
```

Create a authentication token for the `rotate-linux` policy with a 24 hour
lifetime.

```sh
$ vault token create -period 24h -policy rotate-linux
Key                  Value
---                  -----
token                hvs.CAESIA4OZQxuA8RSUeBIKrXe7Ui3...
token_accessor       4I9EZYWOa7LaGh5K6uSpoxO6
token_duration       24h
token_renewable      true
token_policies       ["default" "rotate-linux"]
identity_policies    []
policies             ["default" "rotate-linux"]
```

The `token` value should be used as the `VAULT_TOKEN` on the managed servers,
and both `VAULT_ADDR` and `VAULT_TOKEN` should be present in `/etc/environment`
or equivalent.

### User policies

The user `vagrant` with the password `HorsePassport` using the `ansible` and
`linuxadmin` policies should be created or updated.

On `vault`:

```sh
$ vault write auth/userpass/users/vagrant password="HorsePassport" policies="ansible,linuxadmin"
Success! Data written to: auth/userpass/users/vagrant
```

Copy [rotate_linux_password.sh](scripts/rotate_linux_password.sh) to the managed
servers and generate a password for the user on each server.

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
token                  hvs.CAESILn3hivHCO8UNJmAxGuQjf2RNsj...
token_accessor         jIdHDHIvHhptlM8druMRdDHN
token_duration         768h
token_renewable        true
token_policies         ["ansible" "default" "linuxadmin"]
identity_policies      []
policies               ["ansible" "default" "linuxadmin"]
token_meta_username    vagrant
$ export VAULT_TOKEN='hvs.CAESILn3hivHCO8UNJmAxGuQjf2RNsj...
$ ansible-inventory -i hvault_inventory.py --list --yaml
all:
  children:
    vault_hosts:
      hosts:
        server01:
          ansible_become_password: XKeR2wwovX2YDE8xiRw1jylN1Iuz0neD
          ansible_host: 192.168.56.41
          ansible_password: 275faaa8-ef18-23f6-9077-552e535890d4
          ansible_port: 22
          ansible_user: vagrant
        server02:
          ansible_become_password: 5BFXsysn6vxTkGigdt89ADIzb3o5ZPh7
          ansible_host: 192.168.56.42
          ansible_password: 9ab81420-1ee0-bbdf-f0fd-ecd75250b571
          ansible_port: 22
          ansible_user: vagrant
$ ansible-playbook -i hvault_inventory.py playbook.yml
PLAY [Test Hashicorp Vault dynamic inventory] **********************************

TASK [Get ssh host keys from vault_hosts group] ********************************
# 192.168.56.41:22 SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13
# 192.168.56.41:22 SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13
# 192.168.56.42:22 SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13
# 192.168.56.42:22 SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13
ok: [server02 -> localhost] => (item=server01)
ok: [server01 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server02)
ok: [server01 -> localhost] => (item=server02)

TASK [Print ansible_password] **************************************************
ok: [server01] => {
    "msg": "14c21fcb-0c58-f35b-2b81-114860c96f56"
}
ok: [server02] => {
    "msg": "b3466115-609b-8e0e-78ae-29e7520616fa"
}

TASK [Print ansible_become_password] *******************************************
ok: [server01] => {
    "msg": "XKeR2wwovX2YDE8xiRw1jylN1Iuz0neD"
}
ok: [server02] => {
    "msg": "5BFXsysn6vxTkGigdt89ADIzb3o5ZPh7"
}

TASK [Print ansible_ssh_private_key_file] **************************************
skipping: [server01]
skipping: [server02]

TASK [Stat vault-ssh.log] ******************************************************
ok: [server01]
ok: [server02]

TASK [Grep authentication methods] *********************************************
ok: [server01]
ok: [server02]

TASK [Grep authentication string from /var/log/vault-ssh.log] ******************
ok: [server01]
ok: [server02]

TASK [Grep keyboard-interactive from /var/log/auth.log] ************************
ok: [server01]
ok: [server02]

TASK [Grep serial from ssh journal] ********************************************
skipping: [server01]
skipping: [server02]

TASK [Print authentication methods] ********************************************
ok: [server01] => {
    "msg": "authenticationmethods any"
}
ok: [server02] => {
    "msg": "authenticationmethods any"
}

TASK [Print authentication string] *********************************************
ok: [server01] => {
    "msg": "2025/09/01 20:32:38 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2025/09/01 20:32:38 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [Print keyboard-interactive] **********************************************
ok: [server01] => {
    "msg": "2025-09-01T20:32:38.932876+00:00 vagrant sshd[4916]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.39 port 35338 ssh2"
}
ok: [server02] => {
    "msg": "2025-09-01T20:32:38.970148+00:00 vagrant sshd[4570]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.39 port 34692 ssh2"
}

TASK [Print cert serials] ******************************************************
skipping: [server01]
skipping: [server02]

PLAY RECAP *********************************************************************
server01                   : ok=10   changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
server02                   : ok=10   changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```
