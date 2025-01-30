#!/bin/bash
# Source: https://github.com/scarolan/painless-password-rotation/blob/master/files/rotate_linux_password.sh
# Script for rotating passwords on the local machine.
# Make sure and store VAULT_TOKEN and VAULT_ADDR as environment variables.

set -e -o pipefail

for dep in curl jq logger; do
  if ! command -v "${dep}" 1>/dev/null; then
    echo "Missing dependency: ${dep}. Exiting."
    exit 1
  fi
done

if [ "${VAULT_TOKEN}" = "" ]; then
  echo "VAULT_TOKEN is missing. Exiting."
  exit 1
fi

if [ "${VAULT_ADDR}" = "" ]; then
  echo "VAULT_ADDR is missing. Exiting."
  exit 1
fi

# Check for usage
if [[ $# -ne 1 ]]; then
  echo "Please provide a username."
  echo "Usage: $0 $(id -un)"
  exit 1
fi

USERNAME="$1"

# Make sure the user exists on the local system
if ! id "${USERNAME}" &>/dev/null; then
  echo "${USERNAME} does not exist. Exiting."
  exit 1
fi

# Renew our token before we do anything else
if ! curl -sS --fail -X POST -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/auth/token/renew-self" | grep -q 'request_id'; then
  echo "Error renewing Vault token lease. Exiting."
  exit 1
fi

NEWPASS="$(cat /proc/sys/kernel/random/uuid)"

# Create the JSON payload to write to vault
JSON="{ \"options\": { \"max_versions\": 12 }, \"data\": { \"${USERNAME}\": \"$NEWPASS\" } }"

# First commit the new password to vault, then capture the exit status
if curl -sS --fail -X POST -H "X-Vault-Token: ${VAULT_TOKEN}" --data "$JSON" "${VAULT_ADDR}/v1/systemcreds/data/linux/$(hostname -s)/${USERNAME}_creds"; then
  # After we save the password to vault, update it on the instance
  if echo "${USERNAME}:${NEWPASS}" | sudo chpasswd; then
     logger -p auth.info -t vault "Password for user ${USERNAME} was stored in Vault and updated locally."
  else
     logger --stderr -p auth.err -t vault "Password for ${USERNAME} was stored in Vault but NOT updated locally."
  fi
else
  logger --stderr -p auth.err -t vault "Error saving new password to Vault. Local password will remain unchanged."
  exit 1
fi
