#!/bin/bash
#
# TPM Verify Signature Script
# Usage: ./tmp_verify_signature.sh <data_file> <signature_b64> <tpm_handle>

set -euo pipefail

DATA_FILE="$1"
SIGNATURE_B64="$2"
TPM_HANDLE="$3"

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

# Decode signature
echo "$SIGNATURE_B64" | base64 -d > "$SIGNATURE_FILE"

# Verify signature with TPM
if tpm2_verifysignature -c "$TPM_HANDLE" -g sha256 -s rsassa -m "$DATA_FILE" -s "$SIGNATURE_FILE"; then
    echo "Signature verified"
    exit 0
else
    echo "Signature verification failed" >&2
    exit 1
fi