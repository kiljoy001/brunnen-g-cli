#!/bin/bash
#
# TPM Sign Data Script
# Usage: ./tpm_sign_data.sh <data_file> <tpm_handle>

set -euo pipefail

DATA_FILE="$1"
TPM_HANDLE="$2"

if [[ ! -f "$DATA_FILE" ]]; then
    echo "Error: Data file not found: $DATA_FILE" >&2
    exit 1
fi

if [[ ! "$TPM_HANDLE" =~ ^0x[0-9a-fA-F]{8}$ ]]; then
    echo "Error: Invalid TPM handle format: $TPM_HANDLE" >&2
    exit 1
fi

# Create temporary files
SIGNATURE_FILE=$(mktemp)
trap 'rm -f "$SIGNATURE_FILE"' EXIT

# Sign data with TPM
tpm2_sign -c "$TPM_HANDLE" -g sha256 -s rsassa -o "$SIGNATURE_FILE" "$DATA_FILE"

# Output base64 encoded signature
base64 -w 0 < "$SIGNATURE_FILE"
echo  # newline