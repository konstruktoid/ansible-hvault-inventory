# Using HashiCorp Vault as a dynamic Ansible inventory and authentication service, part 3

```console
Do not use any of this without testing in a non-operational environment.
```

## In summary

`hvault_inventory.py` adds support for [signed SSH Certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
by reading the user public key stored in the Vault K/V secret engine, signs it,
and then saves it as `~/.ssh/ansible_{ANSIBLE_USER}_cert.pub`.

Every time the inventory script is used, the script checks if the certificate
is valid and will renew it if it isn't.

## Vault and host configuration

See [part one](./ssh_otp.md) for configuration of the KV Secrets Engine, where
we added the names and IP addresses of the two hosts that will be managed by Ansible.

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

Follow Hashicorps [Signed SSH certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
documentation regarding creating and adding keys:

```sh
$ vault secrets enable -path=ssh-client-signer ssh
Success! Enabled the ssh secrets engine at: ssh-client-signer/
$ vault write ssh-client-signer/config/ca generate_signing_key=true
Key           Value
---           -----
public_key    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC3UPs3h4+tC1...
$ vault write ssh-client-signer/roles/ssh-certs -<<"EOH"
{
  "algorithm_signer": "rsa-sha2-256",
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allowed_extensions": "permit-pty,permit-port-forwarding",
  "default_extensions": {
    "permit-pty": ""
  },
  "key_type": "ca",
  "default_user": "vagrant",
  "ttl": "30m0s"
}
EOH
$ vault policy write ansible ansible.hcl
$ vault policy write ssh-certs ssh-certs.hcl
$ vault auth enable userpass
Success! Enabled userpass auth method at: userpass/
$ vault write auth/userpass/users/vagrant password="HorsePassport" policies="ansible,ssh-certs"
Success! Data written to: auth/userpass/users/vagrant
```

On `server01` and `server02`:
```sh
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ curl -fsSL "${VAULT_ADDR}/v1/ssh-client-signer/public_key" |\
  sudo tee /etc/ssh/trusted-user-ca-keys.pem
$ echo 'TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem' |\
  sudo tee /etc/ssh/sshd_config.d/90-vault-ca.conf
$ sudo systemctl restart sshd
```

On the `admin` machine, and if you're using `Vagrant` the private key can be
located using `vagrant ssh-config admin | grep 'IdentityFile' | awk '{print $NF}'`.

```sh
$ export VAULT_ADDR='http://192.168.56.40:8200'
$ unset VAULT_TOKEN
$ vault login -method=userpass username=vagrant password=HorsePassport
Success! You are now authenticated. [...]
$ export VAULT_TOKEN='hvs.CAESIByrr...'
$ ssh-keygen -y -f ~/.ssh/id_ed25519 > ~/.ssh/id_ed25519.pub
$ vault write -field=signed_key ssh-client-signer/sign/ssh-certs public_key=@$HOME/.ssh/id_ed25519.pub | ssh-keygen -Lf -
(stdin):1:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:t3/0DcADFGwSgZVfK1fd6qqofzDk3dYfJErmnUq9ABU
        Signing CA: RSA SHA256:U65qkOIWAOfbU1wbFY/pBcMzSmAA64RSQp4oXP2X9Ag (using rsa-sha2-256)
        Key ID: "vault-userpass-vagrant-b77ff40dc003146c1281955f2b57ddeaaaa87f...
        Serial: 18159637528978863254
        Valid: from 2024-02-28T14:50:13 to 2024-02-28T15:20:43
        Principals:
                vagrant
        Critical Options: (none)
        Extensions:
                permit-pty
$ vault write -field=signed_key ssh-client-signer/sign/ssh-certs public_key=@$HOME/.ssh/id_ed25519.pub > .ssh/id_ed25519-cert.pub
$ ssh 192.168.56.41 'sudo journalctl -u ssh | grep ED25519-CERT'
Feb 28 14:59:42 server01 sshd[11586]: Accepted publickey for vagrant from 192...
$ ssh 192.168.56.42 'sudo journalctl -u ssh | grep ED25519-CERT'
Feb 28 14:59:48 server02 sshd[11695]: Accepted publickey for vagrant from 192...
```

Verify that Ansible works as well:

```sh
ansible-playbook --private-key ~/.ssh/id_ed25519-cert.pub -i hvault_inventory.py playbook.yml
```

## Adding user public keys to K/V engine

Convert user public key to a base64 string.

```sh
$ cat ~/.ssh/id_ed25519.pub | base64 -w0
c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQ...
```

Add it to the Vault K/V engine and verify:

```
$ vault kv put -mount=secret user-keys vagrant=c3NoLWVkMjU1MTkgQUFBQUMzTnphQ...
$ vault kv get -field=vagrant -mount=secret user-keys | base64 -d
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINGUK3fVhpzejdnQafOhYIuUs/8tdMYajuQ3nryJm3i/ vagrant
```

Remove `~/.ssh/authorized_keys` on `server01` and `server02`.

On `admin`, add the private key and run the test playbook:

```
$ ssh-add .ssh/id_ed25519
Identity added: .ssh/id_ed25519 (vagrant)
Certificate added: .ssh/id_ed25519-cert.pub (vault-userpass-vagrant-2cbb21473e...)
$ ansible-playbook -i hvault_inventory.py playbook.yml

PLAY [Test Hashicorp Vault dynamic inventory] **********************************

TASK [Get ssh host keys from vault_hosts group] ********************************
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
# 192.168.56.41:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
ok: [server01 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server01)
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
# 192.168.56.42:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
ok: [server01 -> localhost] => (item=server02)
ok: [server02 -> localhost] => (item=server02)

TASK [Print ansible_password] **************************************************
skipping: [server01]
skipping: [server02]

TASK [Print ansible_become_password] *******************************************
skipping: [server01]
skipping: [server02]

TASK [Print ansible_ssh_private_key_file] *************************************
ok: [server01] => {
    "msg": "/home/vagrant/.ssh/ansible_vagrant_cert.pub"
}
ok: [server02] => {
    "msg": "/home/vagrant/.ssh/ansible_vagrant_cert.pub"
}

TASK [Stat vault-ssh.log] ******************************************************
ok: [server01]
ok: [server02]

TASK [Grep authentication string from /var/log/vault-ssh.log] ******************
skipping: [server01]
skipping: [server02]

TASK [Grep keyboard-interactive from /var/log/auth.log] ************************
skipping: [server01]
skipping: [server02]

TASK [Grep keyboard-interactive from /var/log/auth.log] ************************
ok: [server02]
ok: [server01]

TASK [Print authentication string] *********************************************
skipping: [server01]
skipping: [server02]

TASK [Print keyboard-interactive] **********************************************
skipping: [server01]
skipping: [server02]

TASK [Print cert serials] ******************************************************
ok: [server01] => {
    "msg": "Feb 29 21:09:03 server01 sshd[14789]: Accepted publickey for vagrant...
}
ok: [server02] => {
    "msg": "Feb 29 21:08:50 server02 sshd[15200]: Accepted publickey for vagrant...
}
```
