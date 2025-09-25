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
$ vault write ssh-client-signer/roles/ssh-certs -<<"EOF"
{
  "algorithm_signer": "rsa-sha2-512",
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
EOF
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
$ sudo systemctl restart ssh
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
        Public key: ED25519-CERT SHA256:hfub1ct7tQKjjJI+O7IVr0FuzLfbsmcCyp/DnANW2jk
        Signing CA: RSA SHA256:nUXEUxYFJYu93Ch7xAglqpBsU3oiRvPzyuaMCajn2oI (using rsa-sha2-512)
        Key ID: "vault-userpass-vagrant-85fb9bd5cb7bb502a38c923e3bb215af416eccb7dbb26702ca9fc39c0356da39"
        Serial: 2071682612104208897
        Valid: from 2025-01-30T22:58:00 to 2025-01-30T23:28:30
        Principals:
                vagrant
        Critical Options: (none)
        Extensions:
                permit-pty
$ vault write -field=signed_key ssh-client-signer/sign/ssh-certs public_key=@$HOME/.ssh/id_ed25519.pub > .ssh/id_ed25519-cert.pub
$ ssh 192.168.56.41 'sudo journalctl -u ssh | grep ED25519-CERT'
Jan 30 22:59:41 server01 sshd[4360]: Accepted publickey for vagrant from 192.168...
$ ssh 192.168.56.42 'sudo journalctl -u ssh | grep ED25519-CERT'
Jan 30 22:59:54 server02 sshd[4105]: Accepted publickey for vagrant from 192.168...
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

PLAY [Test Hashicorp Vault dynamic inventory] ************************************

TASK [Get ssh host keys from vault_hosts group] **********************************
ok: [server01 -> localhost] => (item=server01)
ok: [server02 -> localhost] => (item=server01)
ok: [server01 -> localhost] => (item=server02)
ok: [server02 -> localhost] => (item=server02)

TASK [Print ansible_password] ****************************************************
ok: [server01] => {
    "msg": "3539242a-526e-acb9-4264-0847c57ce03a"
}
ok: [server02] => {
    "msg": "47732c9c-4286-7a15-a6ee-4a3fdd94a966"
}

TASK [Print ansible_become_password] *********************************************
ok: [server01] => {
    "msg": "d68f2d09-8327-4306-922d-522ebf4e53af"
}
ok: [server02] => {
    "msg": "e3620985-7abb-4c6e-bea6-8e471c1e6dfc"
}

TASK [Print ansible_ssh_private_key_file] ****************************************
ok: [server01] => {
    "msg": "/home/vagrant/.ssh/ansible_vagrant_cert.pub"
}
ok: [server02] => {
    "msg": "/home/vagrant/.ssh/ansible_vagrant_cert.pub"
}

TASK [Stat vault-ssh.log] ********************************************************
ok: [server01]
ok: [server02]

TASK [Grep authentication methods] ***********************************************
ok: [server02]
ok: [server01]

TASK [Grep authentication string from /var/log/vault-ssh.log] ********************
ok: [server01]
ok: [server02]

TASK [Grep keyboard-interactive from /var/log/auth.log] **************************
ok: [server02]
ok: [server01]

TASK [Grep keyboard-interactive from /var/log/auth.log] **************************
ok: [server01]
ok: [server02]

TASK [Print authentication methods] **********************************************
ok: [server01] => {
    "msg": "authenticationmethods any"
}
ok: [server02] => {
    "msg": "authenticationmethods any"
}

TASK [Print authentication string] ***********************************************
ok: [server01] => {
    "msg": "2025/01/30 23:01:27 [INFO] vagrant@192.168.56.41 authenticated!"
}
ok: [server02] => {
    "msg": "2025/01/30 23:01:27 [INFO] vagrant@192.168.56.42 authenticated!"
}

TASK [Print keyboard-interactive] ************************************************
ok: [server01] => {
    "msg": "2025-01-30T23:01:27.981233+00:00 vagrant sshd[4430]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.39 port 43284 ssh2"
}
ok: [server02] => {
    "msg": "2025-01-30T23:01:27.937679+00:00 vagrant sshd[4175]: Accepted keyboard-interactive/pam for vagrant from 192.168.56.39 port 40956 ssh2"
}

TASK [Print cert serials] ********************************************************
ok: [server01] => {
    "msg": "Jan 30 23:07:16 server01 sshd[4847]: Accepted publickey for vagrant...
}
ok: [server02] => {
    "msg": "Jan 30 23:07:15 server02 sshd[4589]: Accepted publickey for vagrant...
}
```
