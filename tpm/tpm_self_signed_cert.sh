#!/bin/bash

set -e

# Configuration
KEY_ALG="RSA"               # Algorithm (RSA/EC)
KEY_SIZE=2048               # Key size for RSA (2048/3072/4096)
CERT_DAYS=365               # Certificate validity in days
OUT_DIR="./certs"           # Output directory
KEY_FILE="$OUT_DIR/tpm.key" # Private key file
CERT_FILE="$OUT_DIR/cert.pem" # Certificate file
SUBJECT="/CN=TPM-Self-Signed" # Certificate subject

# Check dependencies
check_dependencies() {
    command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl required but not found"; exit 1; }
    command -v tpm2_startup >/dev/null 2>&1 || { echo >&2 "tpm2-tools required but not found"; exit 1; }
    
    if [ ! -c /dev/tpm0 ]; then
        echo "TPM device /dev/tpm0 not found"
        exit 1
    fi
}

# Initialize TPM
init_tpm() {
    echo "Initializing TPM..."
    tpm2_startup -c 2>/dev/null || true
}

# Generate certificate
generate_cert() {
    mkdir -p "$OUT_DIR"
    
    echo "Generating TPM-backed private key..."
    openssl genpkey -provider tpm2 -algorithm "$KEY_ALG" -pkeyopt "rsa_keygen_bits:$KEY_SIZE" \
        -out "$KEY_FILE"
    
    echo "Generating self-signed certificate..."
    openssl req -new -x509 -days "$CERT_DAYS" \
        -provider tpm2 -provider default \
        -key "$KEY_FILE" -out "$CERT_FILE" \
        -subj "$SUBJECT"
    
    echo "Certificate generated:"
    openssl x509 -in "$CERT_FILE" -text -noout
}

# Main execution
main() {
    check_dependencies
    init_tpm
    generate_cert
    
    echo -e "\nSuccessfully generated:"
    echo "Private key: $KEY_FILE"
    echo "Certificate: $CERT_FILE"
}

# Run main function
main