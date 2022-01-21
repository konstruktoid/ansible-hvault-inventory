# Source: https://github.com/scarolan/painless-password-rotation/blob/master/policies/rotate-linux.hcl
# Allows hosts to write new passwords
path "systemcreds/data/linux/*" {
  capabilities = ["create", "update"]
}

# Allow hosts to generate new passphrases
path "gen/passphrase" {
  capabilities = ["update"]
}

# Allow hosts to generate new passwords
path "gen/password" {
  capabilities = ["update"]
}
