#!/bin/bash
#
# TPM-Secured Yggdrasil Launcher - Fixed Version
# 
# This script provides enhanced security for Yggdrasil by:
# - Storing private keys in TPM hardware
# - Using in-memory configuration only
# - Securely cleaning up sensitive data
# - Using random TPM handles for unpredictability

# Exit on error, unbound variable, and pipe failures
set -euo pipefail
trap 'echo "Script failed at line $LINENO"; cleanup_on_error; exit 1' ERR

TPM_DIR="/run/yggdrasil"
METADATA_FILE="$TPM_DIR/tpm-handles.json"
LOCK_FILE="/run/yggdrasil/yggdrasil-tpm.lock"
TMP_CONFIG_PATH="/dev/shm/yggdrasil.conf"
TEMP_KEY_FILE=$(mktemp -p /dev/shm)
chmod 600 "$TEMP_KEY_FILE"

# Ensure only one instance runs
acquire_lock() {
    local timeout=30
    local count=0
    
    while ! mkdir "$LOCK_FILE" 2>/dev/null; do
        if [[ $count -ge $timeout ]]; then
            echo "Could not acquire lock after ${timeout}s"
            exit 1
        fi
        echo "Waiting for lock..."
        sleep 1
        ((count++))
    done
    
    # Store PID for cleanup
    echo $$ > "$LOCK_FILE/pid"
    trap 'rm -rf "$LOCK_FILE" 2>/dev/null || true' EXIT
}

cleanup_on_error() {
    echo "Cleaning up after error..."
    shred -u "$TEMP_KEY_FILE" /dev/shm/primary.ctx /dev/shm/key.* 2>/dev/null || true
    rm -rf "$LOCK_FILE" 2>/dev/null || true
}

trap 'shred -u "$TEMP_KEY_FILE" /dev/shm/primary.ctx /dev/shm/key.* 2>/dev/null || true; rm -rf "$LOCK_FILE" 2>/dev/null || true' EXIT

mkdir -p "$TPM_DIR"
acquire_lock

PRIMARY_HANDLE=""
KEY_HANDLE=""

run_checked() {
    "$@" || {
        echo "Command failed: $*"
        exit 1
    }
}

generate_random_handle() {
    local MIN=0x81010000
    local MAX=0x8101FFFF
    printf "0x%08x\n" $((RANDOM % (MAX - MIN + 1) + MIN))
}

handle_exists() {
    local handle_uppercase
    handle_uppercase=$(echo "$1" | tr 'a-f' 'A-F')
    tpm2_getcap handles-persistent 2>/dev/null | grep -q "$handle_uppercase"
}

store_metadata() {
    echo "Storing metadata: Primary=$1, Key=$2"
    local temp_metadata="$METADATA_FILE.tmp"
    cat > "$temp_metadata" <<EOF
{
  "primary_handle": "$1",
  "key_handle": "$2",
  "created_at": $(date +%s),
  "hostname": "$(hostname)",
  "user": "$(whoami)"
}
EOF
    chmod 600 "$temp_metadata"
    mv "$temp_metadata" "$METADATA_FILE"
    echo "Metadata stored at $METADATA_FILE"
}

monitor_and_cleanup() {
    local pid=$1
    local config_path=$2

    while kill -0 "$pid" 2>/dev/null; do
        sleep 2
    done

    echo "Yggdrasil exited (PID $pid), securely deleting config..."
    shred -u "$config_path" 2>/dev/null || true
}

read_metadata() {
    if [[ -f "$METADATA_FILE" ]]; then
        # Validate JSON and extract values safely
        if python3 -m json.tool "$METADATA_FILE" >/dev/null 2>&1; then
            export PRIMARY_HANDLE=$(python3 -c "import json; data=json.load(open('$METADATA_FILE')); print(data.get('primary_handle', ''))")
            export KEY_HANDLE=$(python3 -c "import json; data=json.load(open('$METADATA_FILE')); print(data.get('key_handle', ''))")
            echo "Read metadata: Primary=$PRIMARY_HANDLE, Key=$KEY_HANDLE"
            
            # Verify handles still exist
            if [[ -n "$PRIMARY_HANDLE" && -n "$KEY_HANDLE" ]] && handle_exists "$PRIMARY_HANDLE" && handle_exists "$KEY_HANDLE"; then
                return 0
            else
                echo "Stored handles no longer exist, regenerating..."
                return 1
            fi
        else
            echo "Invalid metadata file, regenerating..."
            rm -f "$METADATA_FILE"
            return 1
        fi
    else
        return 1
    fi
}

create_primary_if_needed() {
    if ! handle_exists "$PRIMARY_HANDLE"; then
        echo "Creating primary key ($PRIMARY_HANDLE)..."
        run_checked tpm2_createprimary -C o -g sha256 -G ecc -c /dev/shm/primary.ctx
        
        # Try to evict, if TPM full then fail gracefully
        if ! tpm2_evictcontrol -C o -c /dev/shm/primary.ctx "$PRIMARY_HANDLE" 2>/dev/null; then
            echo "TPM storage full - cannot create persistent handle"
            echo "Manual cleanup required: tpm2_getcap handles-persistent"
            exit 1
        fi
        rm -f /dev/shm/primary.ctx
    else
        echo "Primary handle exists: $PRIMARY_HANDLE"
    fi
}

seal_key_if_needed() {
    if ! handle_exists "$KEY_HANDLE"; then
        echo "Sealing Yggdrasil key into TPM (handle $KEY_HANDLE)..."
        echo -n "$YGG_KEY" | run_checked tpm2_create -C "$PRIMARY_HANDLE" -i- \
            -u /dev/shm/key.pub -r /dev/shm/key.priv

        run_checked tpm2_load -C "$PRIMARY_HANDLE" -u /dev/shm/key.pub \
            -r /dev/shm/key.priv -c /dev/shm/key.ctx

        run_checked tpm2_evictcontrol -C o -c /dev/shm/key.ctx "$KEY_HANDLE"
        rm -f /dev/shm/key.*
    else
        echo "Key handle exists: $KEY_HANDLE"
    fi
}

unseal_key() {
    echo "Unsealing Yggdrasil key from TPM..."
    run_checked tpm2_unseal -c "$KEY_HANDLE" > "$TEMP_KEY_FILE"
}

# Check if Yggdrasil is already running
if pgrep -f "yggdrasil.*useconffile" >/dev/null; then
    echo "Yggdrasil already running with TPM config"
    exit 0
fi

# Main execution
echo "Setting up TPM-backed Yggdrasil config in RAM..."

if read_metadata; then
    echo "Using previously stored handles"
else
    echo "Generating fresh TPM handles..."
    
    # Generate unique handles with collision avoidance
    PRIMARY_HANDLE=$(generate_random_handle)
    attempts=0
    while handle_exists "$PRIMARY_HANDLE"; do
        if [[ $attempts -ge 20 ]]; then
            echo "Too many handle collisions, aborting"
            exit 1
        fi
        PRIMARY_HANDLE=$(generate_random_handle)
        ((attempts++))
    done

    KEY_HANDLE=$(generate_random_handle)
    attempts=0
    while handle_exists "$KEY_HANDLE" || [[ "$KEY_HANDLE" == "$PRIMARY_HANDLE" ]]; do
        if [[ $attempts -ge 20 ]]; then
            echo "Too many handle collisions for key handle"
            exit 1
        fi
        KEY_HANDLE=$(generate_random_handle)
        ((attempts++))
    done
    
    echo "Generated handles: Primary=$PRIMARY_HANDLE, Key=$KEY_HANDLE"
fi

create_primary_if_needed

echo "Generating Yggdrasil config in /dev/shm..."
run_checked yggdrasil -genconf > "$TMP_CONFIG_PATH"
YGG_KEY=$(awk '/PrivateKey/ {print $2}' "$TMP_CONFIG_PATH")

if [[ -z "$YGG_KEY" ]]; then
    echo "Failed to extract private key from config"
    exit 1
fi

seal_key_if_needed
store_metadata "$PRIMARY_HANDLE" "$KEY_HANDLE"

# Backward compatibility for brunnen-cli.sh
echo "$KEY_HANDLE" > /dev/shm/handle.txt

unseal_key
PRIVATE_KEY=$(cat "$TEMP_KEY_FILE")

if [[ -z "$PRIVATE_KEY" ]]; then
    echo "Failed to unseal private key"
    exit 1
fi

echo "Injecting private key into Yggdrasil config..."
sed "s/PrivateKey: .*/PrivateKey: $PRIVATE_KEY/" "$TMP_CONFIG_PATH" > "$TMP_CONFIG_PATH.new"
mv "$TMP_CONFIG_PATH.new" "$TMP_CONFIG_PATH"

echo "Launching Yggdrasil with in-memory config..."

# Wait for Yggdrasil to start, then exec into it
yggdrasil -useconffile "$TMP_CONFIG_PATH" &
YGG_PID=$!

# Wait for socket
for i in {1..5}; do
    if [[ -S /var/run/yggdrasil.sock ]]; then
        echo "Yggdrasil started successfully"
        break
    fi
    sleep 1
done

# Start background monitor
monitor_and_cleanup "$YGG_PID" "$TMP_CONFIG_PATH" &

echo "Yggdrasil TPM setup complete!"
echo "Primary handle: $PRIMARY_HANDLE"
echo "Key handle: $KEY_HANDLE"

# Keep script running to maintain systemd service
wait $YGG_PID