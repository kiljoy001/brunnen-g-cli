#!/bin/bash

# --- Configuration ---
LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/tpm_setup_$(date +%Y%m%d_%H%M%S).log"
ALLOW_CLEANUP_ON_FAIL=false  # Set to false for debugging partial executions
TPM_PERSISTENT_BASE=0x81000000

# --- Initialization ---
set -o errexit   # Exit script on any error
set -o nounset   # Treat unset variables as errors
set -o pipefail  # Capture pipe command failures

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}" || {
    echo "Failed to create log directory: ${LOG_DIR}" >&2
    exit 1
}

# --- Logging Functions ---
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info() {
    log "INFO" "$1"
}

log_error() {
    log "ERROR" "$1"
    exit 1
}

log_warn() {
    log "WARN" "$1"
}

# --- Cleanup Handler ---
cleanup() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 && ${ALLOW_CLEANUP_ON_FAIL} == true ]]; then
        log_warn "Cleaning up after failure..."

        # Evict persistent handle if created
        if [[ -f handle.txt ]]; then
            local handle=$(cat handle.txt 2>/dev/null)
            tpm2_evictcontrol -C e "${handle}" >/dev/null 2>&1 || true
            log_warn "Evicted persistent handle: ${handle}"
        fi

        # Remove temporary files
        rm -f ek.ctx signing_key.* handle.txt 2>/dev/null
    fi
}
trap cleanup EXIT

# --- Helper Functions ---
validate_tpm_tools() {
    command -v tpm2_createek >/dev/null 2>&1 || {
        log_error "TPM2 tools not found. Please install tpm2-tools package."
    }
}

find_available_handle() {
    local max_attempts=100
    local attempt=0
    local used_handles=()

    log_info "Scanning for available persistent handles..."
    
    # Get current persistent handles
    if ! used_handles=($(tpm2_getcap handles-persistent 2>/dev/null | 
                       awk '/0x[0-9A-Fa-f]+/ {print $1}')); then
        log_error "Failed to query persistent handles from TPM"
    fi

    while (( attempt++ < max_attempts )); do
        # Generate random handle in valid range (0x81000000-0x817FFFFF)
        local offset=$(( RANDOM % 0x800000 ))
        local handle=$(( TPM_PERSISTENT_BASE + offset ))
        local handle_hex=$(printf "0x%08X" ${handle})

        if [[ ! " ${used_handles[@]} " =~ " ${handle_hex} " ]]; then
            echo "${handle_hex}" > handle.txt
            return 0
        fi
    done

    log_error "Failed to find available persistent handle after ${max_attempts} attempts"
}

# --- Check hierarchy for authorization ---
check_hierarchy_auth() {
    if tpm2_getcap properties-variable | grep -q "TPM2_PT_HR_ENDORSEMENT_AUTH_SET=1"; then
        log_warn "Endorsement Hierarchy has authorization set!"
        log_warn "Run: tpm2_changeauth -e -p <current_password> <new_password>"
        log_warn "Or contact your TPM administrator"
        log_error "Cannot proceed with authorization requirements"
    fi
}

# --- Main Execution ---
main() {
    log_info "Starting TPM key provisioning process"
    validate_tpm_tools
    check_hierarchy_auth

    # Find and store persistent handle
    find_available_handle
    persistent_handle=$(cat handle.txt)
    log_info "Persistent handle stored in handle.txt"

    # Create Endorsement Key
    log_info "Creating Endorsement Key (ECC)..."
    if ! tpm2_createek -c ek.ctx -G ecc -u ek.pub >> "${LOG_FILE}" 2>&1; then
        log_error "Failed to create Endorsement Key. Check ${LOG_FILE} for details."
    fi

    # Create Signing Key
    log_info "Generating signing key..."
    if ! tpm2_createak -C ek.ctx -c ak.ctx -G ecc -u signing_key.pub >> "${LOG_FILE}" 2>&1; then
        log_error "Failed to create signing key. Check ${LOG_FILE} for details."
    fi

    # Load and persist key
    log_info "Persisting signing key..."
 
    log_info "Presist handle set to "${persistent_handle}""
    if ! tpm2_evictcontrol -C o -c ak.ctx "${persistent_handle}" >> "${LOG_FILE}" 2>&1; then
        log_error "Failed to persist signing key. Check ${LOG_FILE} for details."
    fi

    # Export public key
    log_info "Exporting public key..."
    if ! tpm2_readpublic -c "${persistent_handle}" -f pem -o signing_key.pem >> "${LOG_FILE}" 2>&1; then
        log_error "Failed to export public key. Check ${LOG_FILE} for details."
    fi

    log_info "TPM provisioning completed successfully"
    log_info "Persistent handle: ${persistent_handle}"
    log_info "Public key: signing_key.pem"
}

# --- Execution Entry Point ---
main