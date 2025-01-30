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
`systemcreds/` path  on the Vault server:

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
          ansible_become_password: uncurled-subtitle-unsocial-tightness-obstruct
          ansible_host: 192.168.56.41
          ansible_password: 7ff78fd7-3e40-6c53-f38d-5661b225f3a5
          ansible_port: 22
          ansible_user: vagrant
        server02:
          ansible_become_password: plethora-plod-jaybird-stopping-eternity
          ansible_host: 192.168.56.42
          ansible_password: 6b7e121d-01db-bea9-10e3-112fc4eb21b6
          ansible_port: 22
          ansible_user: vagrant
$ ansible-playbook -i hvault_inventory.py playbook.yml

PLAY [Test Hashicorp Vault dynamic inventory] *****************************************************

TASK [Get ssh host keys from vault_hosts group] ***************************************************
ok: [server01 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server02)
ok: [server01 -> localhost] => (item=server02)

TASK [Print ansible_password] *********************************************************************
ok: [server01] => {
    "msg": "74fef72d-5649-576b-b6bb-c5aa181ecae6"
}
ok: [server02] => {
    "msg": "6a6eaf29-51a6-82d2-cea5-541892c4c35b"
}

TASK [Print ansible_become_password] **************************************************************
ok: [server01] => {
    "msg": "d68f2d09-8327-4306-922d-522ebf4e53af"
}
ok: [server02] => {
    "msg": "e3620985-7abb-4c6e-bea6-8e471c1e6dfc"
}

TASK [Print ansible_ssh_private_key_file] *********************************************************
skipping: [server01]
skipping: [server02]

TASK [Stat vault-ssh.log] *************************************************************************
ok: [server02]
ok: [server01]

TASK [Grep authentication methods] ****************************************************************
ok: [server02]
ok: [server01]

TASK [Grep authentication string from /var/log/vault-ssh.log] *************************************
ok: [server01]
ok: [server02]

TASK [Grep keyboard-interactive from /var/log/auth.log] *******************************************
ok: [server02]
ok: [server01]

TASK [Grep keyboard-interactive from /var/log/auth.log] *******************************************
skipping: [server01]
skipping: [server02]

TASK [Print authentication methods] ***************************************************************
ok: [server01] => {
    "msg": "authenticationmethods any"
}
ok: [server02] => {
    "msg": "authenticationmethods any"
}

TASK [Print authentication string] *****************************************************************
ok: [server01] => {
    "msg": "2025/01/30 22:39:19 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2025/01/30 22:39:19 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [Print keyboard-interactive] *******************************************************************
ok: [server01] => {
    "msg": "2025-01-30T22:39:19.913210+00:00 vagrant sshd[4079]: Accepted keyboard-interactive/pam...
}
ok: [server02] => {
    "msg": "2025-01-30T22:39:19.923243+00:00 vagrant sshd[3829]: Accepted keyboard-interactive/pam...
}

TASK [Print cert serials] ***************************************************************************
skipping: [server01]
skipping: [server02]
```
