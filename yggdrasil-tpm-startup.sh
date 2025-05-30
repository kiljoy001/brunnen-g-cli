#!/bin/bash
#
# TPM-Secured Yggdrasil Launcher
# 
# This script provides enhanced security for Yggdrasil by:
# - Storing private keys in TPM hardware
# - Using in-memory configuration only
# - Securely cleaning up sensitive data
# - Using random TPM handles for unpredictability

# Exit on error, unbound variable, and pipe failures
set -euo pipefail
trap 'echo "❌ Script failed at line $LINENO"; exit 1' ERR

TPM_DIR="/tpmdata"
METADATA_FILE="$TPM_DIR/handles.json"
TMP_CONFIG_PATH="/dev/shm/yggdrasil.conf"
TEMP_KEY_FILE=$(mktemp -p /dev/shm)
chmod 600 "$TEMP_KEY_FILE"

trap 'shred -u "$TEMP_KEY_FILE" /dev/shm/primary.ctx /dev/shm/key.* 2>/dev/null || true' EXIT

mkdir -p "$TPM_DIR"

PRIMARY_HANDLE=""
KEY_HANDLE=""

run_checked() {
    "$@" || {
        echo "🛑 Command failed: $*"
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
    tpm2_getcap handles-persistent | grep -q "$handle_uppercase"
}

store_metadata() {
    echo "Storing metadata: Primary=$1, Key=$2"
    cat > "$METADATA_FILE" <<EOF
{
  "primary_handle": "$1",
  "key_handle": "$2"
}
EOF
    chmod 600 "$METADATA_FILE"
    echo "Metadata stored at $METADATA_FILE:"
    cat "$METADATA_FILE"
}

monitor_and_cleanup() {
    local pid=$1
    local config_path=$2

    while kill -0 "$pid" 2>/dev/null; do
        sleep 2
    done

    echo "🪟 Yggdrasil exited (PID $pid), securely deleting config..."
    shred -u "$config_path" 2>/dev/null || true
}

read_metadata() {
    if [[ -f "$METADATA_FILE" ]]; then
        export PRIMARY_HANDLE=$(grep -oP '"primary_handle": *"\K[^"]+' "$METADATA_FILE" || echo "")
        export KEY_HANDLE=$(grep -oP '"key_handle": *"\K[^"]+' "$METADATA_FILE" || echo "")
        echo "📁 Read metadata: Primary=$PRIMARY_HANDLE, Key=$KEY_HANDLE"
        [[ -n "$PRIMARY_HANDLE" && -n "$KEY_HANDLE" ]]
    else
        return 1
    fi
}

create_primary_if_needed() {
    if ! handle_exists "$PRIMARY_HANDLE"; then
        echo "🔐 Creating primary key ($PRIMARY_HANDLE)..."
        run_checked tpm2_createprimary -C o -g sha256 -G ecc -c /dev/shm/primary.ctx
        run_checked tpm2_evictcontrol -C o -c /dev/shm/primary.ctx "$PRIMARY_HANDLE"
    else
        echo "✅ Primary handle exists: $PRIMARY_HANDLE"
    fi
}

seal_key_if_needed() {
    if ! handle_exists "$KEY_HANDLE"; then
        echo "🔏 Sealing Yggdrasil key into TPM (handle $KEY_HANDLE)..."
        echo -n "$YGG_KEY" | run_checked tpm2_create -C "$PRIMARY_HANDLE" -i- \
            -u /dev/shm/key.pub -r /dev/shm/key.priv

        run_checked tpm2_load -C "$PRIMARY_HANDLE" -u /dev/shm/key.pub \
            -r /dev/shm/key.priv -c /dev/shm/key.ctx

        run_checked tpm2_evictcontrol -C o -c /dev/shm/key.ctx "$KEY_HANDLE"
    else
        echo "✅ Key handle exists: $KEY_HANDLE"
    fi
}

unseal_key() {
    echo "🔓 Unsealing Yggdrasil key from TPM..."
    run_checked tpm2_unseal -c "$KEY_HANDLE" > "$TEMP_KEY_FILE"
}

# Main execution
echo "⚙️  Setting up TPM-backed Yggdrasil config in RAM..."

if read_metadata; then
    echo "🔁 Using previously stored handles"
else
    echo "🆕 Generating fresh TPM handles..."
    PRIMARY_HANDLE=$(generate_random_handle)
    while handle_exists "$PRIMARY_HANDLE"; do
        PRIMARY_HANDLE=$(generate_random_handle)
    done

    KEY_HANDLE=$(generate_random_handle)
    while handle_exists "$KEY_HANDLE"; do
        KEY_HANDLE=$(generate_random_handle)
    done
fi

create_primary_if_needed

echo "🗘️ Generating Yggdrasil config in /dev/shm..."
run_checked yggdrasil -genconf > "$TMP_CONFIG_PATH"
YGG_KEY=$(awk '/PrivateKey/ {print $2}' "$TMP_CONFIG_PATH")

seal_key_if_needed
store_metadata "$PRIMARY_HANDLE" "$KEY_HANDLE"

unseal_key
PRIVATE_KEY=$(cat "$TEMP_KEY_FILE")

echo "Injecting private key into Yggdrasil config..."
sed "s/PrivateKey: .*/PrivateKey: $PRIVATE_KEY/" "$TMP_CONFIG_PATH" > "$TMP_CONFIG_PATH.new"
mv "$TMP_CONFIG_PATH.new" "$TMP_CONFIG_PATH"

echo "🚀 Launching Yggdrasil with in-memory config..."
run_checked yggdrasil -useconffile "$TMP_CONFIG_PATH" &

YGG_PID=$!

for i in {1..5}; do
    if [[ -S /var/run/yggdrasil.sock ]]; then
        break
    fi
    sleep 1
done

monitor_and_cleanup "$YGG_PID" "$TMP_CONFIG_PATH" &
