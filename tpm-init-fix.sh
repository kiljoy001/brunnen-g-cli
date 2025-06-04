#!/bin/bash

# Initialize TPM for Brunnen-G with proper handle management
init_tpm_master() {
    echo "Initializing TPM master key..."
    
    # Clean any existing contexts
    rm -f /dev/shm/*.ctx 2>/dev/null
    
    # Use a valid persistent handle range (0x81000000 - 0x81FFFFFF)
    local MASTER_HANDLE="0x81000001"
    
    # Check if handle already exists
    if tpm2_getcap handles-persistent | grep -q "$MASTER_HANDLE"; then
        echo "Master handle already exists, clearing..."
        tpm2_evictcontrol -c "$MASTER_HANDLE" 2>/dev/null || true
    fi
    
    # Create primary key in owner hierarchy
    tpm2_createprimary -C o -g sha256 -G rsa -c /dev/shm/master.ctx || {
        echo "Failed to create primary key"
        return 1
    }
    
    # Make it persistent with proper handle
    tpm2_evictcontrol -C o -c /dev/shm/master.ctx "$MASTER_HANDLE" || {
        echo "Failed to make handle persistent"
        # Try alternative approach
        tpm2_evictcontrol -C o -c /dev/shm/master.ctx -o "$MASTER_HANDLE" 2>/dev/null || {
            echo "Alternative evictcontrol also failed"
            return 1
        }
    }
    
    echo "TPM master key initialized at handle: $MASTER_HANDLE"
    echo "$MASTER_HANDLE" > /tpmdata/master_handle.txt
    
    # Clean up context file
    rm -f /dev/shm/master.ctx
    
    return 0
}

# Call the function
init_tpm_master