#!/bin/bash
set -euo pipefail

# Configuration
DEFAULT_OUTPUT="tpm_random.bin"
BYTES=32
ENGINE="tpm2tss"

# Help function
usage() {
    echo "Usage: $0 [-o output_file] [-f hex|bin] [-b bytes]"
    echo "Generate TPM-backed random numbers with OpenSSL"
    echo "Options:"
    echo "  -o  Output file path (default: ${DEFAULT_OUTPUT})"
    echo "  -f  Output format (hex or binary, default: bin)"
    echo "  -b  Number of bytes (default: ${BYTES})"
    exit 1
}

# Parse arguments
while getopts ":o:f:b:" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
        f) FORMAT="$OPTARG" ;;
        b) BYTES="$OPTARG" ;;
        \?) usage ;;
    esac
done

# Set defaults
OUTPUT_FILE="${OUTPUT_FILE:-$DEFAULT_OUTPUT}"
FORMAT="${FORMAT:-bin}"

# Validate format
if [[ "$FORMAT" != "hex" && "$FORMAT" != "bin" ]]; then
    echo "ERROR: Invalid format. Use 'hex' or 'bin'"
    usage
fi

# Validate byte count
if ! [[ "$BYTES" =~ ^[0-9]+$ ]] || [ "$BYTES" -lt 1 ]; then
    echo "ERROR: Bytes must be a positive integer"
    usage
fi

# Check dependencies
check_deps() {
    command -v openssl >/dev/null 2>&1 || {
        echo "ERROR: OpenSSL not found"
        exit 1
    }
    
    # Try different TPM engine names
    for engine_name in "tpm2tss" "tpm2" "tpm2-tss"; do
        if openssl engine "$engine_name" &>/dev/null; then
            ENGINE="$engine_name"
            echo "Found TPM engine: $ENGINE"
            return 0
        fi
    done
    
    echo "WARNING: No TPM2 OpenSSL engine found, using fallback methods"
    ENGINE=""
}

# Generate random data
generate_random() {
    if [[ -n "$ENGINE" ]]; then
        echo "Using TPM hardware random generator..."
        if [[ "$FORMAT" == "hex" ]]; then
            openssl rand -engine "$ENGINE" -hex "$BYTES"
        else
            openssl rand -engine "$ENGINE" -out "$OUTPUT_FILE" "$BYTES"
        fi
    elif command -v tpm2_getrandom >/dev/null 2>&1; then
        echo "Using tpm2_getrandom..."
        if [[ "$FORMAT" == "hex" ]]; then
            tpm2_getrandom --hex "$BYTES" > $OUTPUT_FILE
        else
            tpm2_getrandom -o "$OUTPUT_FILE" "$BYTES"
        fi
    else
        echo "Using system random generator..."
        if [[ "$FORMAT" == "hex" ]]; then
            openssl rand -hex "$BYTES"
        else
            openssl rand -out "$OUTPUT_FILE" "$BYTES"
        fi
    fi
}

# Main execution
main() {
    check_deps
    
    echo "Generating ${BYTES} random bytes..."
    generate_random
    
    # Only set permissions if file was created
    if [[ -f "$OUTPUT_FILE" ]]; then
        chmod 600 "$OUTPUT_FILE"
        echo "Success: Random data saved to ${OUTPUT_FILE}"
        echo "SHA-256: $(openssl dgst -sha256 "$OUTPUT_FILE")"
    else
        echo -e "\nError: Output file not created"
        exit 1
    fi
}

# Run main function
main