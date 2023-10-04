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
Root Token: hvs.vDkyJoiMWV3JuBn9sqd7g307
The following dev plugins are registered in the catalog:
    - vault-secrets-gen

$ export VAULT_ADDR='http://192.168.56.40:8200'
$ export VAULT_TOKEN='hvs.vDkyJoiMWV3JuBn9sqd7g307'
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
token                hvs.CAESIA4OZQxuA8RSUeBIKrXe7Ui3wtrb0LDR0hb8xPlH2s8NGh4KHGh2cy45S2Zoc3lMS2tlYnp6dDJZTG5qS1VHVkM
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
token                  hvs.CAESILn3hivHCO8UNJmAxGuQjf2RNsj9Y0E_SPMklriwU42FGh4KHGh2cy44NXQ1b3lIOTRFUTFRdGVSNm1LUG9ZNDE
token_accessor         jIdHDHIvHhptlM8druMRdDHN
token_duration         768h
token_renewable        true
token_policies         ["ansible" "default" "linuxadmin"]
identity_policies      []
policies               ["ansible" "default" "linuxadmin"]
token_meta_username    vagrant
$ export VAULT_TOKEN='hvs.CAESILn3hivHCO8UNJmAxGuQjf2RNsj9Y0E_SPMklriwU42FGh4KHGh2cy44NXQ1b3lIOTRFUTFRdGVSNm1LUG9ZNDE'
$ ansible-inventory -i /vagrant/hvault_inventory.py --list --yaml
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
$ ansible-playbook -i /vagrant/hvault_inventory.py /vagrant/playbook.yml

PLAY [Test Hashicorp Vault dynamic inventory] **********************************

TASK [Get ssh host keys from vault_hosts group] ********************************
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
ok: [server01 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server01)
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
ok: [server01 -> localhost] => (item=server02)
ok: [server02 -> localhost] => (item=server02)

TASK [Print ansible_password] **************************************************
ok: [server01] => {
    "msg": "52e11780-81a4-0c21-b31b-0d2f9ffbc147"
}
ok: [server02] => {
    "msg": "d8396f42-1305-bd03-0a46-c4dcab2075f9"
}

TASK [Print ansible_become_password] *******************************************
ok: [server01] => {
    "msg": "uncurled-subtitle-unsocial-tightness-obstruct"
}
ok: [server02] => {
    "msg": "plethora-plod-jaybird-stopping-eternity"
}

TASK [Grep authentication string from /var/log/vault-ssh.log] ******************
ok: [server02]
ok: [server01]

TASK [Grep keyboard-interactive from /var/log/auth.log] ************************
ok: [server02]
ok: [server01]

TASK [Print authentication string] *********************************************
ok: [server01] => {
    "msg": "2023/10/04 20:18:18 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2023/10/04 20:18:16 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [Print keyboard-interactive] **********************************************
ok: [server01] => {
    "msg": "Oct  4 20:18:18 ubuntu-jammy sshd[4125]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.39 port 55592 ssh2"
}
ok: [server02] => {
    "msg": "Oct  4 20:18:16 ubuntu-jammy sshd[4441]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.39 port 49700 ssh2"
}

PLAY RECAP *********************************************************************
server01                   : ok=7    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
server02                   : ok=7    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```
