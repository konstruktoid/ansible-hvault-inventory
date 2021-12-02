path "secret/data/ansible-hosts" {
  capabilities = ["read", "create", "update"]
}

path "ssh/*" {
  capabilities = [ "list" ]
}

path "ssh/creds/otp_key_role" {
  capabilities = ["create", "read", "update"]
}
