#!/bin/bash
trap 'shred -u /dev/shm/.brunnen_challenge /dev/shm/handle.txt /dev/shm/yubikey_pub.pem /dev/shm/enc_key.* /dev/shm/key.* /dev/shm/primary.ctx /dev/shm/tmp_pub.pem /dev/shm/linked_cert.pem /dev/shm/sign_data /dev/shm/signature /dev/shm/verify_data /dev/shm/verify_sig /dev/shm/api_sign_data /dev/shm/api_signature /dev/shm/api_verify_data /dev/shm/api_verify_sig /dev/shm/yubikey_cert.pem /dev/shm/yubikey_pub.pem /dev/shm/provisioning_new.json 2>/dev/null || true' EXIT INT TERM

generate_yubikey_cert() {
    local address="$1"
    local tmp_handle="$2"
    
    echo "Generating YubiKey certificate tied to TPM..."
    
    # Get TPM public key for hash linking
    tpm2_readpublic -c "$tmp_handle" -f pem -o /dev/shm/tmp_pub.pem
    
    # Generate YubiKey key and self-signed certificate
    ykman piv keys generate 9a /dev/shm/yubikey_pub.pem
    sudo chmod 666 /dev/shm/tpm_pub.pem /dev/shm/yubikey_pub.pem 2>/dev/null || true
    ykman piv certificates generate 9a /dev/shm/yubikey_pub.pem \
        --subject "CN=$address,O=Brunnen-G,OU=TPM-YubiKey" \
        /dev/shm/linked_cert.pem
    
    # Import certificate to YubiKey
    ykman piv certificates import 9a /dev/shm/linked_cert.pem
    
    # Generate combined hash for linking TPM + YubiKey
    combined_hash=$(cat /dev/shm/tmp_pub.pem /dev/shm/yubikey_pub.pem | sha256sum | cut -d' ' -f1)
    
    echo "YubiKey cert installed. Combined hash: $combined_hash"
    
    # Update database
    sqlite3 "$DB_NAME" "UPDATE address_keys SET yubikey_hash = '$combined_hash' WHERE address = '$address';"
    
    # Cleanup (will be handled by trap)
}

verify_yubikey_identity() {
    echo "=== Verify YubiKey Identity ==="
    
    ykman piv certificates export 9a /dev/shm/yubikey_cert.pem
    
    cert_subject=$(openssl x509 -in /dev/shm/yubikey_cert.pem -noout -subject | grep -o 'CN=[^,]*' | cut -d'=' -f2)
    domain="${cert_subject#*@}"
    
    echo "Certificate identity: $cert_subject"
    echo "Domain: $domain"
    
    domain_data=$(emercoin-cli name_show "dns:$domain" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "[FAIL] Domain not found on blockchain"
        return 1
    fi
    
    cid=$(echo "$domain_data" | jq -r '.cid // empty')
    if [[ -z "$cid" ]]; then
        echo "[FAIL] No CID found for domain"
        return 1
    fi
    
    echo "Found CID: $cid"
    
    ipfs get "$cid" -o "/dev/shm/remote_db"
    
    result=$(sqlite3 "/dev/shm/remote_db" "SELECT yubikey_hash FROM address_keys WHERE address = '$cert_subject';" 2>/dev/null)
    
    if [[ -z "$result" ]]; then
        echo "[FAIL] Identity not found in domain database"
        return 1
    fi
    
    ykman piv keys export 9a /dev/shm/yubikey_pub.pem
    current_hash=$(cat /dev/shm/yubikey_cert.pem /dev/shm/yubikey_pub.pem | sha256sum | cut -d' ' -f1)
    
    if [[ "$current_hash" == "$result" ]]; then
        echo "[OK] YubiKey verified against blockchain identity"
        echo "Identity: $cert_subject"
        echo "Hash match: $current_hash"
    else
        echo "[FAIL] YubiKey hash mismatch"
        echo "Expected: $result"
        echo "Current: $current_hash"
    fi
    
    rm -f /dev/shm/yubikey_cert.pem /dev/shm/yubikey_pub.pem /dev/shm/remote_db
}

HACKER_MODE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --hacker-mode)
            HACKER_MODE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--hacker-mode]"
            exit 1
            ;;
    esac
done

# DGA database naming
generate_db_name() {
    local seed=$(hostname)$(whoami)
    local hash=$(echo "$seed" | sha256sum | cut -c1-12)
    echo "${hash}.db"
}

DB_NAME="./data/$(generate_db_name)"

# Check TPM permissions
check_tpm_access() {
    if [[ $EUID -eq 0 ]] || groups | grep -q tss; then
        return 0
    else
        echo "Warning: TPM operations require root or tss group membership"
        return 1
    fi
}

# Safe TPM operation wrapper
run_tpm_script() {
    local script="$1"
    shift
    
    if ! check_tpm_access; then
        echo "Attempting to run with sudo..."
        sudo "$script" "$@"
    else
        "$script" "$@"
    fi
}

# create_database - builds the distributed database that holds public key data
create_database() {
    mkdir -p ./data
    sqlite3 "$DB_NAME" "
    CREATE TABLE IF NOT EXISTS address_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL UNIQUE,
        pubkey TEXT NOT NULL,
        TPM_key TEXT,
        TPM_enable BOOLEAN DEFAULT 1,
        yubikey_hash TEXT DEFAULT '',
        row_hash BLOB
    );
    
    CREATE TABLE IF NOT EXISTS db_root (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        table_name TEXT NOT NULL,
        root BLOB NOT NULL,
        row_hash BLOB
    );

    CREATE TABLE IF NOT EXISTS tpm_domain_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        TPM_enable BOOLEAN DEFAULT 1,
        row_hash BLOB
    );
    "
    echo "Database created: $DB_NAME"
}

verify_domain_ownership() {
    local domain=$1
    primary_handle=$(cat /dev/shm/handle.txt 2>/dev/null)
    domain_info=$(emercoin-cli name_show "dns:$domain" 2>&1)
    if [[ $? -ne 0 ]]; then
        echo "Domain not found on blockchain"
        return 1
    fi
    
    echo "Domain found: $domain"
    
    # List wallets
    wallets=$(emercoin-cli listwallets | jq -r '.[]')
    echo "Available wallets:"
    IFS=$'\n' read -rd '' -a wallet_array <<< "$wallets"
    
    for i in "${!wallet_array[@]}"; do
        echo "$((i+1))) ${wallet_array[i]}"
    done
    
    echo -n "Select wallet: "
    read wallet_choice
    selected_wallet="${wallet_array[$((wallet_choice-1))]}"
    
    echo -n "Enter domain owner address: "
    read domain_address
    
    # Check if wallet is encrypted
    wallet_info=$(emercoin-cli -rpcwallet="$selected_wallet" getwalletinfo 2>&1)
    if echo "$wallet_info" | grep -q '"unlocked_until": 0'; then
        echo -n "Wallet locked. Enter passphrase: "
        read -s passphrase
        echo
        emercoin-cli -rpcwallet="$selected_wallet" walletpassphrase "$passphrase" 60
    fi
    
    # Generate and sign challenge
    challenge=$(openssl rand -hex 32)
    echo "Challenge: $challenge"
    
    signature=$(emercoin-cli -rpcwallet="$selected_wallet" signmessage "$domain_address" "$challenge")
    if [[ $? -ne 0 ]]; then
        echo "Signature failed"
        return 1
    fi
    
    echo "Domain ownership verified"
    
    # Check for existing domain seed
    if decrypt_metadata 2>/dev/null && [[ -f "/dev/shm/provisioning.json" ]]; then
        existing_seed=$(jq -r ".domain_settings[\"$domain\"].seed // empty" /dev/shm/provisioning.json)
        encrypt_metadata

        if [[ -n "$existing_seed" && "$existing_seed" != "empty" ]]; then
            echo "Using existing domain seed"
            domain_seed="$existing_seed"
            return 0
        fi
    fi
    echo "primary handle is $primary_handle"
    if [[ -z "$primary_handle" || "$primary_handle" == "empty" ]]; then
        echo "Primary handle not found - run yggdrasil startup first"
        return 1
    fi
    tmp_domain_key=$(tpm2_readpublic -c "$primary_handle" -f der | xxd -p)
    combined_data="$tmp_domain_key$domain_pubkey"
    domain_seed=$(emercoin-cli -rpcwallet="$selected_wallet" signmessage "$domain_address" "$combined_data" | sha512sum | cut -c1-128)
    
    # Store in encrypted metadata
    store_domain_seed "$domain" "$domain_seed"
    return 0
}

calculate_row_hash() {
    local table=$1
    local id=$2
    
    case $table in
        "address_keys")
            row_data=$(sqlite3 "$DB_NAME" "SELECT address || '|' || pubkey || '|' || COALESCE(TPM_key,'') || '|' || TPM_enable || '|' || COALESCE(yubikey_hash,'') FROM address_keys WHERE id = $id")
            row_hash=$(echo -n "$row_data" | sha256sum | cut -d' ' -f1)
            sqlite3 "$DB_NAME" "UPDATE address_keys SET row_hash = '$row_hash' WHERE id = $id"
            ;;
        "tpm_domain_settings")
            row_data=$(sqlite3 "$DB_NAME" "SELECT domain || '|' || TPM_enable FROM tpm_domain_settings WHERE id = $id")
            row_hash=$(echo -n "$row_data" | sha256sum | cut -d' ' -f1)
            sqlite3 "$DB_NAME" "UPDATE tpm_domain_settings SET row_hash = '$row_hash' WHERE id = $id"
            ;;
        "db_root")
            row_data=$(sqlite3 "$DB_NAME" "SELECT table_name || '|' || hex(root) FROM db_root WHERE id = $id")
            row_hash=$(echo -n "$row_data" | sha256sum | cut -d' ' -f1)
            sqlite3 "$DB_NAME" "UPDATE db_root SET row_hash = '$row_hash' WHERE id = $id"
            ;;
    esac
}

build_table_merkle() {
    local table=$1
    local temp_file="/dev/shm/hashes_$$"
    
    sqlite3 "$DB_NAME" "SELECT row_hash FROM $table ORDER BY id;" > "$temp_file"
    
    while [ $(wc -l < "$temp_file") -gt 1 ]; do
        if [ $(($(wc -l < "$temp_file") % 2)) -eq 1 ]; then
            tail -1 "$temp_file" >> "$temp_file"
        fi
        
        awk 'NR%2==1{h1=$0; getline h2; print h1 h2}' "$temp_file" | \
        while read combined; do
            echo -n "$combined" | sha256sum | cut -d' ' -f1
        done > "${temp_file}.new"
        
        mv "${temp_file}.new" "$temp_file"
    done
    
    merkle_root=$(cat "$temp_file")
    shred -u "$temp_file"
    
    sqlite3 "$DB_NAME" "INSERT OR REPLACE INTO db_root (table_name, root) VALUES ('$table', '$merkle_root')"
    echo "$merkle_root"
}

update_all_merkle_roots() {
    sqlite3 "$DB_NAME" "DELETE FROM db_root"
    
    sqlite3 "$DB_NAME" "SELECT id FROM address_keys;" | while read id; do
        calculate_row_hash "address_keys" "$id"
    done
    
    sqlite3 "$DB_NAME" "SELECT id FROM tpm_domain_settings;" | while read id; do
        calculate_row_hash "tpm_domain_settings" "$id"
    done
    
    build_table_merkle "address_keys"
    build_table_merkle "tpm_domain_settings"
    
    sqlite3 "$DB_NAME" "SELECT id FROM db_root;" | while read id; do 
         calculate_row_hash "db_root" "$id"
    done

    build_table_merkle "db_root"
    
    final_root=$(sqlite3 "$DB_NAME" "SELECT root FROM db_root WHERE table_name='db_root'")
    echo "Final merkle root: $final_root"
}

# Tiered storage: CBOR → IPFS → BitTorrent
store_data() {
    local data="$1"
    local name="${2:-$(echo -n "$data" | sha256sum | cut -c1-16)}"
    local publish="${3:-false}"
    local domain="${4}"
    local size=${#data}
    local ygg_addr=$(get_yggdrasil_address)
    
    mkdir -p ./data/storage/ ./data/torrents/
    
    if [[ $size -lt 15360 ]]; then  # 15KB
        cbor_data=$(echo "$data" | python3 -c "import cbor2, sys; print(cbor2.dumps(sys.stdin.read()).hex())")
        storage_ref="cbor:$cbor_data"
    elif [[ $size -lt 5368709120 ]]; then  # 5GB
        cid=$(echo "$data" | ipfs add -Q)
        storage_ref="ipfs:$cid"
    else
        echo "$data" > "./data/storage/${name}"
        transmission-create "./data/storage/${name}" -t "http://[$ygg_addr]:6969/announce" -o "./data/torrents/${name}.torrent"
        
        torrent_data=$(base64 -w 0 < "./data/torrents/${name}.torrent")
        cbor_package=$(python3 -c "import cbor2; print(cbor2.dumps({'tracker': 'http://[$ygg_addr]:6969/announce', 'torrent_data': '$torrent_data'}).hex())")
        storage_ref="cbor:$cbor_package"
    fi
    
    if [[ "$publish" == "true" && -n "$domain" ]]; then
        risk_key="risk:$(echo -n "$data" | sha256sum | cut -c1-16)"
        publish_risk_data "$risk_key" "${storage_ref#cbor:}" "$domain"
    fi
    
    echo "$storage_ref"
}

publish_risk_data() {
    local risk_key="$1"
    local cbor_data="$2"
    local domain="$3"
    
    if verify_domain_ownership "$domain"; then
        emercoin-cli -rpcwallet="$selected_wallet" name_update "risk:$risk_key" "$cbor_data" 365
        echo "Published risk data: risk:$risk_key"
    fi
}

retrieve_data() {
    local storage_ref="$1"
    local type="${storage_ref%%:*}"
    local ref="${storage_ref#*:}"
    
    case $type in
        cbor)
            echo "$ref" | xxd -r -p | python3 -c "import cbor2, sys; print(cbor2.load(sys.stdin.buffer))"
            ;;
        ipfs)
            ipfs cat "$ref"
            ;;
        bt)
            echo "BitTorrent hash: $ref (manual download required)"
            ;;
    esac
}

publish_to_emercoin() {
    local domain="$1"
    local cid="$2" 
    local merkle_root="$3"
    local ygg_addr=$(get_yggdrasil_address)
    
    # Get existing DNS data
    existing_data=$(emercoin-cli name_show "dns:$domain" 2>/dev/null | jq -r '.value // "{}"')
    
    # Parse existing DNS records
    existing_json=$(echo "$existing_data" | jq -r '. // {}')
    
    # Add brunnen-g data without destroying DNS
    updated_json=$(echo "$existing_json" | jq \
        --arg cid "$cid" \
        --arg merkle "$merkle_root" \
        '. + {
            "trust": {
                "cid": $cid,
                "merkle_root": $merkle
            }
        }')
    
    echo "Publishing to Emercoin NVS..."
    echo "Domain: dns:$domain"
    echo "Updated data: $updated_json"
    
    if verify_domain_ownership "$domain"; then
        emercoin-cli -rpcwallet="$selected_wallet" name_update "dns:$domain" "$updated_json" 365
        echo "Published to blockchain (DNS records preserved)"
    fi
}

register_identity() {
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [IDENTITY_REGISTER] ===\033[0m"
    else
        echo "=== Register Identity (TPM Required) ==="
    fi
    echo -n "Username: "
    read username
    echo -n "Domain: "
    read domain
    
    if ! verify_domain_ownership "$domain"; then
        echo "Domain ownership verification failed"
        return 1
    fi
    
    address="${username}@${domain}"
    
    # Check for existing encrypted metadata using your existing decrypt function
    if [[ -f "/tpmdata/provisioning.enc" ]]; then
        if [[ "$HACKER_MODE" == "1" ]]; then
            echo -e "\033[37mmetadata.exists:\033[0m checking identity..."
        else
            echo "Found existing encrypted metadata, checking for identity..."
        fi
        
        # Try to decrypt existing metadata using existing function
        if decrypt_metadata 2>/dev/null; then
            EXISTING_HANDLE=$(jq -r ".identities[\"$address\"].tmp_handle // empty" /tpmdata/provisioning.json 2>/dev/null)
            
            if [[ -n "$EXISTING_HANDLE" ]] && [[ "$EXISTING_HANDLE" != "empty" ]]; then
                if [[ "$HACKER_MODE" == "1" ]]; then
                    echo -e "\033[32m[FOUND]\033[0m tmp_handle: $EXISTING_HANDLE"
                else
                    echo "Found existing TPM handle for $address: $EXISTING_HANDLE"
                fi
                
                # Verify handle still exists in TPM
                if tpm2_getcap handles-persistent | grep -q "$(echo "$EXISTING_HANDLE" | tr 'a-f' 'A-F')"; then
                    if [[ "$HACKER_MODE" == "1" ]]; then
                        echo -e "\033[32m[VERIFIED]\033[0m reusing.identity"
                    else
                        echo "TPM handle verified, reusing existing identity"
                    fi
                    
                    # Update database with existing handle
                    tmp_handle="$EXISTING_HANDLE"
                    tmp_pubkey=$(tpm2_readpublic -c "$tmp_handle" -f der | xxd -p -c 256)
                    
                    create_database
                    sqlite3 "$DB_NAME" "INSERT OR REPLACE INTO address_keys (address, pubkey, TPM_key, TPM_enable, yubikey_hash) 
                                       VALUES ('$address', '$tmp_pubkey', '$tmp_handle', 1, '');"
                    
                    if [[ "$HACKER_MODE" == "1" ]]; then
                        echo -e "\033[32m[SUCCESS]\033[0m identity.registered: $address"
                        echo -e "\033[37mtmp_handle:\033[0m $tmp_handle"
                    else
                        echo "Identity registered: $address"
                        echo "TPM handle: $tmp_handle"
                    fi
                    return 0
                else
                    if [[ "$HACKER_MODE" == "1" ]]; then
                        echo -e "\033[33m[WARNING]\033[0m handle.missing, generating.new"
                    else
                        echo "Stored handle no longer exists in TPM, generating new one"
                    fi
                fi
            fi
            # Re-encrypt after reading
            encrypt_metadata 2>/dev/null
        else
            if [[ "$HACKER_MODE" == "1" ]]; then
                echo -e "\033[31m[ERROR]\033[0m yubikey.decrypt.failed"
                echo -e "\033[37minfo:\033[0m insert yubikey and try again"
            else
                echo "Failed to decrypt metadata - YubiKey required"
                echo "Please insert your YubiKey and try again"
            fi
            return 1
        fi
    fi
    
    # Generate new TPM handle
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m[CRYPTO]\033[0m generating.tmp_keypair"
    else
        echo "Generating TPM keypair..."
    fi
    
    if ! run_tpm_script ./tpm/tpm_provisioning.sh; then
        echo "TPM setup failed - cannot register without TPM"
        return 1
    fi
    
    tmp_handle=$(cat /dev/shm/handle.txt)
    tmp_pubkey=$(tpm2_readpublic -c "$tmp_handle" -f der | xxd -p -c 256)
    
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[37mtmp_handle:\033[0m $tmp_handle"
    else
        echo "Generated new TPM handle: $tmp_handle"
    fi
    
    # Store identity in metadata and encrypt with YubiKey using existing functions
    store_identity_metadata "$address" "$tmp_handle"
    
    create_database
    sqlite3 "$DB_NAME" "INSERT OR REPLACE INTO address_keys (address, pubkey, TPM_key, TPM_enable, yubikey_hash) 
                       VALUES ('$address', '$tmp_pubkey', '$tmp_handle', 1, '');"
    
    echo -n "Add YubiKey certificate? (y/n): "
    read yubikey_choice
    
    if [[ "$yubikey_choice" == "y" ]]; then
        if command -v ykman >/dev/null; then
            generate_yubikey_cert "$address" "$tmp_handle"
            if [[ "$HACKER_MODE" == "1" ]]; then
                echo -e "\033[32m[SUCCESS]\033[0m identity.registered: TPM + YubiKey"
            else
                echo "Identity registered with TPM + YubiKey"
            fi
        else
            if [[ "$HACKER_MODE" == "1" ]]; then
                echo -e "\033[33m[WARNING]\033[0m yubikey.tools.missing"
            else
                echo "YubiKey tools not found (install yubikey-manager)"
            fi
        fi
    else
        if [[ "$HACKER_MODE" == "1" ]]; then
            echo -e "\033[32m[SUCCESS]\033[0m identity.registered: TPM only"
        else
            echo "Identity registered with TPM only"
        fi
    fi
    
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m[SUCCESS]\033[0m identity.registered: $address"
    else
        echo "Identity registered: $address"
        echo "TPM handle: $tmp_handle"
    fi
}

store_domain_seed() {
    local domain="$1"
    local domain_seed="$2"
    
    mkdir -p ./tpmdata
    
    if [[ -f "./tpmdata/provisioning.json" ]]; then
        jq --arg domain "$domain" --arg seed "$domain_seed" \
           '.domain_settings[$domain] = {
               "seed": $seed,
               "created_at": now
           }' ./tpmdata/provisioning.json > /dev/shm/provisioning_new.json
        mv /dev/shm/provisioning_new.json ./tpmdata/provisioning.json
    else
        jq -n --arg domain "$domain" --arg seed "$domain_seed" \
           '{
               "identities": {},
               "domain_settings": {
                   ($domain): {
                       "seed": $seed,
                       "created_at": now
                   }
               },
               "version": "2.0"
           }' > ./tpmdata/provisioning.json
    fi
    
    encrypt_metadata
}

# Store identity in metadata file and encrypt with YubiKey using existing functions
store_identity_metadata() {
    local address="$1"
    local tmp_handle="$2"
    
    # Ensure /tpmdata directory exists
    mkdir -p ./tpmdata
    
    # Create or update provisioning.json
    if [[ -f "./tpmdata/provisioning.json" ]]; then
        # Update existing file
        jq --arg addr "$address" --arg handle "$tmp_handle" \
           '.identities[$addr] = {
               "tmp_handle": $handle,
               "created_at": now,
               "encryption_method": "yubikey_aes"
           }' ./tpmdata/provisioning.json > /dev/shm/provisioning_new.json
        mv /dev/shm/provisioning_new.json ./tpmdata/provisioning.json
    else
        # Create new file
        jq -n --arg addr "$address" --arg handle "$tmp_handle" \
           '{
               "identities": {
                   ($addr): {
                       "tmp_handle": $handle,
                       "created_at": now,
                       "encryption_method": "yubikey_aes"
                   }
               },
               "domain_settings": {},
               "version": "2.0"
           }' > ./tpmdata/provisioning.json
    fi
    
    # Encrypt with YubiKey using existing function
    if encrypt_metadata; then
        if [[ "$HACKER_MODE" == "1" ]]; then
            echo -e "\033[32m[CRYPTO]\033[0m metadata.encrypted.yubikey"
        else
            echo "Metadata encrypted with YubiKey"
        fi
    else
        if [[ "$HACKER_MODE" == "1" ]]; then
            echo -e "\033[31m[ERROR]\033[0m metadata.encryption.failed"
        else
            echo "Failed to encrypt metadata with YubiKey"
        fi
        return 1
    fi
}





query_user() {
    echo "=== Query User ==="
    echo -n "Enter user@domain.(coin, emc, lib, bazar): "
    read user_address
    
    result=$(sqlite3 "$DB_NAME" "SELECT pubkey FROM address_keys WHERE address = '$user_address';" 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        echo "User found locally:"
        echo "Address: $user_address"
        echo "Public Key: $result"
    else
        echo "User not found in local database"
    fi
}

verify_identity() {
    echo "=== Verify Identity ==="
    echo -n "Enter {user}@domain.(coin, emc, lib, bazar): "
    read user_address
    
    result=$(sqlite3 "$DB_NAME" "SELECT address, pubkey, TPM_enable FROM address_keys WHERE address = '$user_address';" 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        echo "[OK] Identity verified"
        echo "Address: $user_address"
        echo "Found in database"
    else
        echo "[FAIL] Identity not found"
        return 1
    fi
}

sign_data() {
    echo "=== Sign Data (TPM) ==="
    echo -n "Your identity {user}@domain.(coin, emc, lib, bazar): "
    read signer
    echo -n "Data to sign: "
    read data
    
    handle=$(sqlite3 "$DB_NAME" "SELECT TPM_key FROM address_keys WHERE address = '$signer' AND TPM_enable = 1;" 2>/dev/null)
    
    if [[ -z "$handle" ]]; then
        echo "TPM key not found for $signer"
        return 1
    fi
    
    echo -n "$data" > /dev/shm/sign_data
    if run_tpm_script tpm2_sign -c "$handle" -g sha256 -o /dev/shm/signature /dev/shm/sign_data; then
        signature=$(base64 -w 0 < /dev/shm/signature)
        echo "TPM Signature: $signature"
        echo "Data: $data"
        echo "Signer: $signer"
        rm -f /dev/shm/sign_data /dev/shm/signature
    else
        echo "TPM signing failed"
    fi
}

verify_signature() {
    echo "=== Verify TPM Signature ==="
    echo -n "Signer {user}@domain.(coin, emc, lib, bazar): "
    read signer
    echo -n "Original data: "
    read data
    echo -n "Signature (base64): "
    read signature
    
    pubkey=$(sqlite3 "$DB_NAME" "SELECT TPM_key FROM address_keys WHERE address = '$signer' AND TPM_enable = 1;" 2>/dev/null)
    
    if [[ -z "$pubkey" ]]; then
        echo "TPM key not found for $signer"
        return 1
    fi
    
    echo -n "$data" > /dev/shm/verify_data
    echo "$signature" | base64 -d > /dev/shm/verify_sig
    
    if run_tpm_script tpm2_verifysignature -c "$pubkey" -g sha256 -m /dev/shm/verify_data -s /dev/shm/verify_sig; then
        echo "[OK] TPM signature valid"
    else
        echo "[FAIL] Invalid TPM signature"
    fi
    
    rm -f /dev/shm/verify_data /dev/shm/verify_sig
}

verify_remote_identity() {
    local user_address="$1"
    local domain="${user_address#*@}"
    
    domain_info=$(emercoin-cli name_show "dns:$domain" 2>/dev/null | jq -r '.yggdrasil // empty')
    
    if [[ -n "$domain_info" ]]; then
        echo "Querying remote domain via Yggdrasil: [$domain_info]"
        remote_result=$(curl -s "http://[$domain_info]:8080/api/query?address=$user_address" 2>/dev/null)
        
        if [[ -n "$remote_result" ]]; then
            echo "Remote verification result:"
            echo "$remote_result" | jq '.'
        else
            echo "Failed to contact remote domain"
        fi
    else
        echo "No Yggdrasil address found for domain: $domain"
    fi
}

get_yggdrasil_address() {
    sudo yggdrasilctl getSelf 2>/dev/null | grep -oE '200:[a-f0-9:]+' || echo ""
}

start_yggdrasil() {
    if pgrep yggdrasil >/dev/null; then
        echo "Yggdrasil already running"
        return 0
    fi
    
    echo "Starting TPM-secured Yggdrasil..."
    if sudo systemctl start yggdrasil; then
        sleep 3
        local ygg_addr=$(get_yggdrasil_address || echo "none")
        echo "Yggdrasil started: $ygg_addr"
        return 0
    else
        echo "Failed to start Yggdrasil"
        return 1
    fi
}

stop_yggdrasil() {
    if ! pkill yggdrasil 2>/dev/null; then
        sudo pkill yggdrasil 2>/dev/null || echo "Failed to stop yggdrasil"
    fi
    echo "Yggdrasil stopped"
}


# API Configuration
API_PORT=${API_PORT:-8080}
HMAC_KEY_FILE="/dev/shm/api_hmac_key"
API_LOG="/dev/shm/brunnen_api.log"

init_api_key() {
    if [[ ! -f "$HMAC_KEY_FILE" ]]; then
        echo "Generating API HMAC key..."
        if run_tpm_script ./tpm/tpm_random_number.sh -b 32 -f hex -o "$HMAC_KEY_FILE"; then
            echo "TPM-generated HMAC key created"
        else
            openssl rand -hex 32 > "$HMAC_KEY_FILE"
            echo "System-generated HMAC key created"
        fi
        chmod 600 "$HMAC_KEY_FILE"
    fi
    HMAC_KEY=$(cat "$HMAC_KEY_FILE")
}

verify_hmac() {
    local payload="$1"
    local received_hmac="$2"
    local expected_hmac=$(echo -n "$payload" | openssl dgst -sha256 -hmac "$HMAC_KEY" | cut -d' ' -f2)
    [[ "$received_hmac" == "$expected_hmac" ]]
}

generate_hmac() {
    local payload="$1"
    echo -n "$payload" | openssl dgst -sha256 -hmac "$HMAC_KEY" | cut -d' ' -f2
}

api_register() {
    local username="$1"
    local domain="$2"
    
    address="${username}@${domain}"
    
    if run_tpm_script ./tpm/tpm_provisioning.sh; then
        tmp_handle=$(cat handle.txt)
        tmp_pubkey=$(tpm2_readpublic -c "$tpm_handle" -f der | xxd -p -c 256)
        
        create_database
        sqlite3 "$DB_NAME" "INSERT INTO address_keys (address, pubkey, TPM_key, TPM_enable) 
                           VALUES ('$address', '$tpm_pubkey', '$tmp_handle', 1);"
        
        echo "{\"status\":\"success\",\"address\":\"$address\",\"tpm_handle\":\"$tmp_handle\"}"
    else
        echo "{\"status\":\"error\",\"message\":\"TPM provisioning failed\"}"
    fi
}

api_query() {
    local address="$1"
    
    result=$(sqlite3 "$DB_NAME" "SELECT pubkey FROM address_keys WHERE address = '$address';" 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        echo "{\"status\":\"success\",\"address\":\"$address\",\"pubkey\":\"$result\"}"
    else
        echo "{\"status\":\"error\",\"message\":\"User not found\"}"
    fi
}

api_verify() {
    local address="$1"
    
    result=$(sqlite3 "$DB_NAME" "SELECT address FROM address_keys WHERE address = '$address';" 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        echo "{\"status\":\"success\",\"verified\":true,\"address\":\"$address\"}"
    else
        echo "{\"status\":\"error\",\"verified\":false,\"message\":\"Identity not found\"}"
    fi
}

api_sign() {
    local signer="$1"
    local data="$2"
    
    handle=$(sqlite3 "$DB_NAME" "SELECT TPM_key FROM address_keys WHERE address = '$signer';" 2>/dev/null)
    
    if [[ -n "$handle" ]]; then
        echo -n "$data" > /dev/shm/api_sign_data
        if tpm2_sign -c "$handle" -g sha256 -o /dev/shm/api_signature /dev/shm/api_sign_data; then
            signature=$(base64 -w 0 < /dev/shm/api_signature)
            echo "{\"status\":\"success\",\"signature\":\"$signature\"}"
        else
            echo "{\"status\":\"error\",\"message\":\"Signing failed\"}"
        fi
        rm -f /dev/shm/api_sign_data /dev/shm/api_signature
    else
        echo "{\"status\":\"error\",\"message\":\"Signer not found\"}"
    fi
}

api_verify_sig() {
    local signer="$1"
    local data="$2"
    local signature="$3"
    
    handle=$(sqlite3 "$DB_NAME" "SELECT TPM_key FROM address_keys WHERE address = '$signer';" 2>/dev/null)
    
    if [[ -n "$handle" ]]; then
        echo -n "$data" > /dev/shm/api_verify_data
        echo "$signature" | base64 -d > /dev/shm/api_verify_sig
        
        if tpm2_verifysignature -c "$handle" -g sha256 -m /dev/shm/api_verify_data -s /dev/shm/api_verify_sig; then
            echo "{\"status\":\"success\",\"verified\":true}"
        else
            echo "{\"status\":\"success\",\"verified\":false}"
        fi
        rm -f /dev/shm/api_verify_data /dev/shm/api_verify_sig
    else
        echo "{\"status\":\"error\",\"message\":\"Signer not found\"}"
    fi
}

send_response() {
    local status="$1"
    local content="$2"
    local hmac=$(generate_hmac "$content")
    
    echo "HTTP/1.1 $status"
    echo "Content-Type: application/json"
    echo "Content-Length: ${#content}"
    echo "X-HMAC-SHA256: $hmac"
    echo "Access-Control-Allow-Origin: *"
    echo ""
    echo "$content"
}

start_api_daemon() {
   local pid_file="/tmp/brunnen_api.pid"
   
   if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
       echo "API already running (PID: $(cat "$pid_file"))"
       return 0
   fi
   
   init_api_key
   echo "Starting Python API daemon on port $API_PORT..."
   
   python3 api_daemon.py &
   echo $! > "$pid_file"
   echo "API daemon started (PID: $!)"
}

stop_api_daemon() {
   local pid_file="/dev/shm/brunnen_api.pid"
   
   if [[ -f "$pid_file" ]]; then
       local pid=$(cat "$pid_file")
       if kill -0 "$pid" 2>/dev/null; then
           kill "$pid"
           echo "API daemon stopped"
       else
           echo "API daemon not running"
       fi
       rm -f "$pid_file"
   else
       echo "No API daemon found"
   fi
}

# Auto-start all services
auto_start() {
    echo "Starting all services..."
    start_yggdrasil
    start_api_daemon
    echo "All services started"
}

# IPFS Integration
publish_database_ipfs() {
    echo "Publishing database to IPFS..."
    update_all_merkle_roots
    cid=$(ipfs add -Q "$DB_NAME")
    echo "Database CID: $cid"
    ipfs pin add "$cid"
    echo "$cid"
}

download_remote_database() {
    local domain="$1"
    
    domain_data=$(emercoin-cli name_show "dns:$domain" 2>/dev/null)
    cid=$(echo "$domain_data" | jq -r '.cid // empty')
    
    if [[ -n "$cid" ]]; then
        echo "Downloading database for $domain (CID: $cid)"
        ipfs get "$cid" -o "/dev/shm/${domain}_db"
        echo "Downloaded to /dev/shm/${domain}_db"
    else
        echo "No CID found for domain: $domain"
        return 1
    fi
}

sync_with_peers() {
    echo "Discovering IPFS peers..."
    ipfs swarm peers | head -5
    
    echo "Syncing with Yggdrasil peers..."
    yggdrasilctl getPeers | grep -oE '200:[a-f0-9:]+' | while read peer; do
        timeout 5 curl -s "http://[$peer]:8080/api/key" >/dev/null && echo "Found peer: $peer"
    done
}
validate_address() {
    [[ "$1" =~ ^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.(coin|emc|lib|bazar)$ ]]
}

validate_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9.-]+\.(coin|emc|lib|bazar)$ ]]
}

manage_api_keys() {
    case "$1" in
        create)
            echo -n "App name: "
            read app_name
            echo -n "Permissions (read,write,admin): "
            read perms
            api_key=$(openssl rand -hex 32)
            
            sqlite3 "$DB_NAME" "INSERT INTO api_keys (app_name, api_key, permissions, created_at) 
                               VALUES ('$app_name', '$api_key', '$perms', $(date +%s));"
            
            echo "API Key created: $api_key"
            echo "Save this key - it cannot be retrieved later"
            ;;
        list)
            sqlite3 "$DB_NAME" "SELECT app_name, permissions, last_used FROM api_keys;"
            ;;
        revoke)
            echo -n "App name to revoke: "
            read app_name
            sqlite3 "$DB_NAME" "DELETE FROM api_keys WHERE app_name = '$app_name';"
            echo "API key revoked"
            ;;
    esac
}

check_expiry() {
    # Domain DNS record
    local domain_expires=$(emercoin-cli name_show "dns:$domain" 2>/dev/null | jq -r '.expires_in // 0')
    
    # Trust database
    local trust_expires=$(emercoin-cli name_show "trust:$domain" 2>/dev/null | jq -r '.expires_in // 0')
    
    if [[ $domain_expires -lt 30 ]]; then
        echo -e "\033[33m[Warning]\033[0m Domain expires in $domain_expires days!"
    fi
    
    if [[ $trust_expires -lt 30 ]]; then
        echo -e "\033[33m[Warning]\033[0m Trust database expires in $trust_expires days!"
    fi
}

publish_risk_data() {
    local risk_id="$1"
    local data="$2"
    local domain="${3:-$(whoami).coin}"
    
    if ! verify_domain_ownership "$domain"; then
        echo "Domain ownership verification failed"
        return 1
    fi
    
    # Encode data with CBOR
    cbor_data=$(echo "$data" | python3 -c "import cbor2, sys, json; print(cbor2.dumps(json.loads(sys.stdin.read())).hex())")
    
    echo "Publishing risk data: risk:$risk_id"
    
    # Publish to blockchain
    emercoin-cli -rpcwallet="$selected_wallet" name_new "risk:$risk_id" "$cbor_data" 365
    
    if [[ $? -eq 0 ]]; then
        echo -e "\033[32m[Success]\033[0m Risk data published: risk:$risk_id"
    else
        echo -e "\033[31m[Failure]\033[0m Risk data publishing failed"
        return 1
    fi
}

enable_wazuh_monitoring() {
    echo "Enabling Wazuh monitoring..."
    
    # Check if Wazuh is installed
    if [[ ! -S "/var/ossec/queue/ossec/queue" ]]; then
        echo "[ERROR] Wazuh not installed or not running"
        echo "Install Wazuh agent first: https://documentation.wazuh.com/current/installation-guide/"
        return 1
    fi
    
    # Enable monitoring
    python3 wazuh_monitor.py enable
    
    if [[ $? -eq 0 ]]; then
        echo "[SUCCESS] Wazuh monitoring enabled"
        echo "Events will be logged to Wazuh SIEM"
    else
        echo "[ERROR] Failed to enable monitoring"
    fi
}

disable_wazuh_monitoring() {
    echo "Disabling Wazuh monitoring..."
    python3 wazuh_monitor.py disable
    
    if [[ $? -eq 0 ]]; then
        echo "[SUCCESS] Wazuh monitoring disabled"
    else
        echo "[ERROR] Failed to disable monitoring"
    fi
}

check_wazuh_status() {
    echo "Checking Wazuh monitoring status..."
    
    # Check if Wazuh agent is running
    if systemctl is-active --quiet wazuh-agent; then
        echo "[OK] Wazuh agent is running"
    else
        echo "[WARNING] Wazuh agent not running"
    fi
    
    # Check if monitoring is enabled
    python3 wazuh_monitor.py status
    
    # Check socket availability
    if [[ -S "/var/ossec/queue/ossec/queue" ]]; then
        echo "[OK] Wazuh socket available"
    else
        echo "[ERROR] Wazuh socket not found"
    fi
}

test_wazuh_connection() {
    echo "Testing Wazuh connection..."
    python3 wazuh_monitor.py test
    
    if [[ $? -eq 0 ]]; then
        echo "[SUCCESS] Test event sent to Wazuh"
        echo "Check Wazuh dashboard for 'brunnen-g' events"
    else
        echo "[ERROR] Failed to send test event"
    fi
}

encrypt_metadata() {
    if [[ ! -f "/dev/shm/provisioning.json" ]]; then
        echo "No metadata to encrypt"
        return 1
    fi
    
    current_hash=$(sha256sum /dev/shm/provisioning.json | cut -d' ' -f1)
    stored_hash=$(cat ./tpmdata/provisioning.hash 2>/dev/null || echo "")
    
    if [[ "$current_hash" != "$stored_hash" ]]; then
        # Data changed, generate new challenge
        challenge=$(openssl rand 32 | xxd -p -c 32)
        echo "$challenge" > /dev/shm/.brunnen_challenge
        echo "$current_hash" > ./tpmdata/provisioning.hash
        echo "Generated new challenge for changed metadata"
    else
        # Data unchanged, reuse challenge
        challenge=$(cat /dev/shm/.brunnen_challenge)
        echo "Reusing existing challenge"
    fi
    
    aes_key=$(ykchalresp -2 -x "$challenge")
    openssl enc -aes-256-cbc -in /dev/shm/provisioning.json \
        -out ./tpmdata/provisioning.enc -k "$aes_key"
    
    chmod 600 ./tpmdata/provisioning.enc /dev/shm/.brunnen_challenge
    shred -u /dev/shm/provisioning.json
    echo "Metadata encrypted with YubiKey"
}

decrypt_metadata() {
    if [[ ! -f "./tpmdata/provisioning.enc" ]]; then
        echo "No encrypted metadata found"
        return 1
    fi
    
    # Ensure tpmdata directory exists and is writable
    if [[ ! -w "./tpmdata" ]]; then
        echo "Cannot write to ./tpmdata directory"
        return 1
    fi
    
    challenge=$(cat /dev/shm/.brunnen_challenge)
    aes_key=$(ykchalresp -2 -x "$challenge")
    # debug
    echo "yubi token key: $aes_key"
    openssl enc -aes-256-cbc -d -in ./tpmdata/provisioning.enc \
        -out /dev/shm/provisioning.json -k "$aes_key"
    echo "Metadata decrypted"
}

quick_setup() {
    echo "=== Quick Setup ==="
    start_yggdrasil
    register_identity
    start_api_daemon
    echo "Setup complete! Your identity is registered and services are running."
}

echo -e "\033[32m"
echo "
██████╗ ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗███╗   ██╗       ██████╗ 
██╔══██╗██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝████╗  ██║      ██╔════╝ 
██████╔╝██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██╔██╗ ██║█████╗██║  ███╗
██╔══██╗██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║╚██╗██║╚════╝██║   ██║
██████╔╝██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║ ╚████║      ╚██████╔╝
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝       ╚═════╝ 
                        Decentralized Public Key Infrastructure
"
echo -e "\033[36mcybersec.mesh_authenticated\033[0m"
identity_menu() {
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [IDENTITY_CORE] ===\033[0m"
        echo -e "\033[32m1) query\033[0m.\033[37muser_lookup\033[0m"
        echo -e "\033[32m2) crypto\033[0m.\033[37msign_message\033[0m"
        echo -e "\033[32m3) verify\033[0m.\033[37msignature_check\033[0m"
    else
        echo "=== Identity ==="
        echo "1) Query user"
        echo "2) Sign message"  
        echo "3) Verify signature"
    fi
    
    case $choice in
        1) query_user ;;
        2) sign_data ;;
        3) verify_signature ;;
    esac
}

network_menu() {
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [MESH_PROTOCOL] ===\033[0m"
        echo -e "\033[32m1) blockchain\033[0m.\033[37mpublish_data\033[0m"
        echo -e "\033[32m2) voip\033[0m.\033[37mconfigure_node\033[0m"
        echo -e "\033[32m3) messaging\033[0m.\033[37msend_encrypted\033[0m"
    else
        echo "=== Network ==="
        echo "1) Publish to blockchain (requires domain ownership)"
        echo "2) Configure VoIP"
        echo "3) Send message (coming soon)"
        echo -n "Choice: "
    fi
    read choice
    
    case $choice in
        1) 
            echo -n "Enter YOUR domain: "
            read domain
            echo "Preparing to publish to $domain..."
            echo "You'll need to prove ownership next."
            
            cid=$(publish_database_ipfs)
            merkle_root=$(sqlite3 "$DB_NAME" "SELECT root FROM db_root WHERE table_name='db_root';")
            publish_to_emercoin "$domain" "$cid" "$merkle_root"
            ;;
        2) configure_voip ;;
        3) echo "Messaging not yet implemented" ;;
    
    esac
}

advanced_menu() {
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [ROOT_ACCESS] ===\033[0m"
        echo -e "\033[32m1) api\033[0m.\033[37mkey_management\033[0m"
        echo -e "\033[32m2) database\033[0m.\033[37moperations\033[0m"
        echo -e "\033[32m3) tmp\033[0m.\033[37mmaintenance\033[0m"
        echo -e "\033[32m4) wazuh\033[0m.\033[37mmonitoring\033[0m"
    else
        echo "=== Advanced Settings ==="
        echo "1) Manage API keys"
        echo "2) Database operations"
        echo "3) TPM maintenance"
        echo "4) Wazuh monitoring"

    fi
    echo -n "Choice: "
    
    read choice
    case $choice in
        1) echo "1) Create  2) List  3) Revoke"
            echo -n "API action: "
            read api_choice
            case $api_choice in
                1) manage_api_keys "create" ;;
                2) manage_api_keys "list" ;;
                3) manage_api_keys "revoke" ;;
            esac
            ;;
        2) database_operations ;;
        3) tmp_maintenance ;;
        4) wazuh_menu ;;
        *) echo "Invalid choice" ;;
    esac
}

wazuh_menu() {
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [MONITORING_CORE] ===\033[0m"
        echo -e "\033[32m1) wazuh\033[0m.\033[37menable\033[0m"
        echo -e "\033[32m2) wazuh\033[0m.\033[37mdisable\033[0m" 
        echo -e "\033[32m3) wazuh\033[0m.\033[37mstatus\033[0m"
        echo -e "\033[32m4) wazuh\033[0m.\033[37mtest\033[0m"
    else
        echo "=== Wazuh Monitoring ==="
        echo "1) Enable monitoring"
        echo "2) Disable monitoring"
        echo "3) Check status"
        echo "4) Test connection"
    fi
    echo -n "Choice: "
    
    read choice
    case $choice in
        1) enable_wazuh_monitoring ;;
        2) disable_wazuh_monitoring ;;
        3) check_wazuh_status ;;
        4) test_wazuh_connection ;;
        *) echo "Invalid choice" ;;
    esac
}

database_operations() {
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [DATABASE_CORE] ===\033[0m"
        echo -e "\033[32m1) export\033[0m.\033[37mbackup_file\033[0m"
        echo -e "\033[32m2) ipfs\033[0m.\033[37mpublish_db\033[0m"
        echo -e "\033[32m3) merkle\033[0m.\033[37mview_roots\033[0m"
        echo -e "\033[32m4) verify\033[0m.\033[37mintegrity\033[0m"
    else
        echo "=== Database Operations ==="
        echo "1) Export database"
        echo "2) Backup to IPFS"
        echo "3) View merkle roots"
        echo "4) Check integrity"
    fi
    echo -n "Choice: "
    read choice
    
    case $choice in
        1) cp "$DB_NAME" "/dev/shm/backup_$(date +%s).db"; echo "Exported" ;;
        2) publish_database_ipfs ;;
        3) sqlite3 "$DB_NAME" "SELECT * FROM db_root;" ;;
        4) update_all_merkle_roots ;;
    esac
}

tmp_maintenance() {
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [TPM_SECURE] ===\033[0m"
        echo -e "\033[32m1) tpm\033[0m.\033[37mview_handles\033[0m"
        echo -e "\033[32m2) crypto\033[0m.\033[37mencrypt_metadata\033[0m"
        echo -e "\033[32m3) crypto\033[0m.\033[37mdecrypt_metadata\033[0m"
        echo -e "\033[32m4) keygen\033[0m.\033[37mdomain_key\033[0m"
    else
        echo "=== TPM Maintenance ==="
        echo "1) View TPM handles"
        echo "2) Encrypt metadata (YubiKey)"
        echo "3) Decrypt metadata (YubiKey)"
        echo "4) Generate domain key"
    fi
    echo -n "Choice: "
    read choice
    
    case $choice in
        1) tmp2_getcap handles-persistent ;;
        2) encrypt_metadata ;;
        3) decrypt_metadata ;;
        4) run_tpm_script ./tpm/tpm_provisioning.sh ;;
    esac
}

while true; do
    if [[ "$HACKER_MODE" == "1" ]]; then
        echo -e "\033[32m=== [SYSTEM_ACCESS] ===\033[0m"
        echo -e "\033[32m1) init\033[0m.\033[37midentity_bootstrap\033[0m"
        echo -e "\033[32m2) query\033[0m.\033[37muser_database\033[0m" 
        echo -e "\033[32m3) mesh\033[0m.\033[37mnetwork_ops\033[0m"
        echo -e "\033[32m4) admin\033[0m.\033[37mroot_access\033[0m"
        echo -e "\033[32m5) logout\033[0m.\033[37msecure\033[0m"
    else
        echo "=== Brunnen-G ==="
        echo "1) Quick Setup (Register + Start Services)"
        echo "2) Identity Operations"
        echo "3) Network & Communication"
        echo "4) Advanced Settings"
        echo "5) Exit"
    fi
    echo -n "Choice: "
    
    read choice
    case $choice in
        1) quick_setup ;;
        2) identity_menu ;;
        3) network_menu ;;
        4) advanced_menu ;;
        5) 
            if [[ "$HACKER_MODE" == "1" ]]; then
                echo -e "\033[32m=== [SYSTEM_EXIT] ===\033[0m"
                echo -e "\033[32m1) shutdown\033[0m.\033[37mstop_services_exit\033[0m"
                echo -e "\033[32m2) logout\033[0m.\033[37mkeep_services_running\033[0m"
            else
                echo "=== Exit Options ==="
                echo "1) Stop services and exit"
                echo "2) Exit (keep services running)"
            fi
            echo -n "Choice: "
            read exit_choice
            case $exit_choice in
                1) stop_api_daemon; stop_yggdrasil; exit 0 ;;
                2) exit 0 ;;
            esac
            ;;
            esac
done