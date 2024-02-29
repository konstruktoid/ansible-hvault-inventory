path "secret/data/user-keys" {
  capabilities = ["read"]
}

path "ssh-client-signer/roles/*" {
 capabilities = ["list"]
}

path "ssh-client-signer/sign/ssh-certs" {
 capabilities = ["create", "update"]
}
