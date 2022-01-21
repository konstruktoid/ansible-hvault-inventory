# Source: https://github.com/scarolan/painless-password-rotation/blob/master/policies/linuxadmin.hcl
# Allows admins to read passwords.
path "systemcreds/*" {
  capabilities = ["list"]
}
path "systemcreds/data/linux/*" {
  capabilities = ["list", "read"]
}
