#!/bin/bash
trap 'cleanup_temp_files' EXIT INT TERM

# Cleanup function
cleanup_temp_files() {
    # Use shred for sensitive files in /dev/shm
    shred -u /dev/shm/.brunnen_challenge 2>/dev/null || true
    shred -u /dev/shm/handle.txt 2>/dev/null || true
    shred -u /dev/shm/yubikey_pub.pem 2>/dev/null || true
    shred -u /dev/shm/provisioning.json 2>/dev/null || true
    shred -u /dev/shm/*.pem 2>/dev/null || true
    shred -u /dev/shm/enc_key.* 2>/dev/null || true
    shred -u /dev/shm/key.* 2>/dev/null || true
    shred -u /dev/shm/primary.ctx 2>/dev/null || true
    shred -u /dev/shm/tmp_pub.pem 2>/dev/null || true
    shred -u /dev/shm/linked_cert.pem 2>/dev/null || true
    shred -u /dev/shm/sign_data 2>/dev/null || true
    shred -u /dev/shm/signature 2>/dev/null || true
    shred -u /dev/shm/verify_data 2>/dev/null || true
    shred -u /dev/shm/verify_sig 2>/dev/null || true
    shred -u /dev/shm/api_sign_data 2>/dev/null || true
    shred -u /dev/shm/api_signature 2>/dev/null || true
    shred -u /dev/shm/api_verify_data 2>/dev/null || true
    shred -u /dev/shm/api_verify_sig 2>/dev/null || true
    shred -u /dev/shm/yubikey_cert.pem 2>/dev/null || true
    shred -u /dev/shm/provisioning_new.json 2>/dev/null || true
    
    # Regular rm for non-sensitive temp files
    rm -f /tmp/.brunnen_domain_address_tmp 2>/dev/null || true
}

# Replace generate_random_handle() function with:
generate_random_handle() {
    # Use valid persistent handle range
    local MIN=0x81000000
    local MAX=0x810FFFFF
    printf "0x%08x\n" $((RANDOM % (MAX - MIN + 1) + MIN))
}

# Update create_primary_if_needed() function:
create_primary_if_needed() {
    if ! handle_exists "$PRIMARY_HANDLE"; then
        echo "Creating primary key ($PRIMARY_HANDLE)..."
        # Use RSA for better compatibility
        run_checked tpm2_createprimary -C o -g sha256 -G rsa -c /dev/shm/primary.ctx
        run_checked tpm2_evictcontrol -C o -c /dev/shm/primary.ctx "$PRIMARY_HANDLE"
    else
        echo "Primary handle exists: $PRIMARY_HANDLE"
    fi
}

# Update handle_exists() to be case-insensitive:
handle_exists() {
    local handle_uppercase=$(echo "$1" | tr 'a-f' 'A-F')
    local handle_lowercase=$(echo "$1" | tr 'A-F' 'a-f')
    tpm2_getcap handles-persistent | grep -qiE "$handle_uppercase|$handle_lowercase"
}

# Spending control functions for brunnen-g-cli.sh
verify_admin_status() {
    echo "=== Verify Admin Status ==="
    echo "Insert YubiKey and press Enter..."
    read
    
    if ! ykman piv certificates export 9a /tmp/verify.pem 2>/dev/null; then
        echo "Failed to read YubiKey"
        return 1
    fi
    
    cert_hash=$(openssl x509 -in /tmp/verify.pem -outform DER | sha256sum | cut -d' ' -f1)
    
    role=$(sqlite3 "$DB_NAME" "SELECT role FROM admin_auth WHERE yubikey_cert_hash = '$cert_hash'")
    
    if [[ -n "$role" ]]; then
        echo "[OK] YubiKey is authorized as: $role"
        echo "Certificate hash: ${cert_hash:0:16}..."
    else
        echo "[FAIL] YubiKey is not an admin"
    fi
    
    rm -f /tmp/verify.pem
}

init_admin_setup() {
    echo "=== One-Time Admin Setup ==="
    
    # Check if already initialized
    if [[ -f "${DB_NAME}.setup" ]]; then
        echo "Setup already complete"
        return 0
    fi

    # Check if TPM master key already exists
    if tpm2_getcap handles-persistent | grep -q "0x81800000"; then
        echo "TPM master key already exists"
    else
        # Create semaphore lock
        exec 200>/var/lock/brunnen_admin_setup.lock
        if ! flock -n 200; then
            echo "Setup already in progress"
            return 1
        fi
        
        echo "Generating TPM master key..."
        
        # Clear any existing handle first
        tpm2_evictcontrol -C o -c 0x81800000 2>/dev/null || true
        
        # Create primary key
        tpm2_createprimary -C o -g sha256 -G aes -c /tmp/master.ctx
        
        # Make persistent
        tpm2_evictcontrol -C o -c /tmp/master.ctx 0x81800000
        rm -f /tmp/master.ctx
        
        # Release lock
        flock -u 200
    fi
    
    echo "Starting initial admin setup..."
    
    # Initialize database tables
    init_spending_tables
    
    # Setup admin YubiKey
    echo "Insert admin YubiKey and press Enter..."
    read
    
    if ! ykman piv certificates export 9a /tmp/admin_cert.pem; then
        echo "Failed to read YubiKey"
        return 1
    fi
    
    admin_cert_hash=$(openssl x509 -in /tmp/admin_cert.pem -outform DER | sha256sum | cut -d' ' -f1)
    
    sqlite3 "$DB_NAME" "INSERT INTO admin_auth 
                       (yubikey_cert_hash, role, created_at, created_by)
                       VALUES ('$admin_cert_hash', 'super_admin', $(date +%s), 'initial_setup');"
    
    # Set initial spending limits
    configure_spending_limits
    
    # Mark setup complete
    echo "{\"setup_date\": $(date +%s), \"admin\": \"$admin_cert_hash\"}" > "${DB_NAME}.setup"
    
    echo "Admin setup complete!"
    rm -f /tmp/admin_cert.pem
}

init_spending_tables() {
    sqlite3 "$DB_NAME" "
    CREATE TABLE IF NOT EXISTS admin_auth (
        yubikey_cert_hash TEXT PRIMARY KEY,
        role TEXT DEFAULT 'admin',
        created_at INTEGER,
        created_by TEXT,
        last_auth INTEGER
    );
    
    CREATE TABLE IF NOT EXISTS spending_limits (
        id INTEGER PRIMARY KEY,
        encrypted_data BLOB NOT NULL,
        nonce BLOB NOT NULL,
        updated_at INTEGER,
        updated_by TEXT
    );
    
    CREATE TABLE IF NOT EXISTS transaction_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        action TEXT NOT NULL,
        amount REAL,
        balance_before REAL,
        balance_after REAL,
        authorized_by TEXT,
        status TEXT,
        details TEXT
    );
    
    CREATE TABLE IF NOT EXISTS action_permissions (
        action TEXT PRIMARY KEY,
        require_yubikey BOOLEAN DEFAULT 1,
        max_amount REAL,
        daily_limit REAL
    );"
}

configure_spending_limits() {
    echo "=== Configure Spending Limits ==="
    
    # Verify admin YubiKey
    if ! verify_admin_yubikey; then
        echo "Admin authentication required"
        return 1
    fi
    
    echo "Current limits:"
    show_spending_limits
    
    echo -n "Daily total limit (EMC): "
    read daily_total
    echo -n "Per transaction limit (EMC): "
    read per_tx
    echo -n "Blockchain posting limit (EMC): "
    read blockchain_limit
    
    # Create JSON limits
    limits_json="{
        \"daily_total\": $daily_total,
        \"per_transaction\": $per_tx,
        \"blockchain_posting\": $blockchain_limit,
        \"auto_approve_threshold\": 0.1
    }"
    
    # Encrypt using TPM
    echo "$limits_json" > /tmp/limits.json
    
    # Generate key material from TPM
    tpm2_hmac -c 0x81800000 --hex "brunnen-g-spending-limits" -o /tmp/key.bin
    
    # Encrypt with openssl (simplified version)
    openssl enc -aes-256-cbc -salt -in /tmp/limits.json -out /tmp/limits.enc \
            -pass file:/tmp/key.bin
    
    # Store encrypted limits
    sqlite3 "$DB_NAME" "INSERT INTO spending_limits 
                       (encrypted_data, nonce, updated_at, updated_by)
                       VALUES (readfile('/tmp/limits.enc'), randomblob(12), 
                               $(date +%s), '$admin_cert_hash');"
    
    # Set action permissions
    sqlite3 "$DB_NAME" "INSERT OR REPLACE INTO action_permissions 
                       (action, require_yubikey, max_amount, daily_limit)
                       VALUES 
                       ('blockchain_post', 1, $blockchain_limit, $(echo "$blockchain_limit * 10" | bc)),
                       ('ipfs_pin', 0, 1.0, 100.0),
                       ('domain_register', 1, 5.0, 20.0);"
    
    echo "Spending limits configured"
    
    # Cleanup
    shred -u /tmp/limits.json /tmp/limits.enc /tmp/key.bin 2>/dev/null || true
}

verify_admin_yubikey() {
    echo "Insert admin YubiKey and press Enter..."
    read
    
    if ! ykman piv certificates export 9a /tmp/verify_cert.pem 2>/dev/null; then
        echo "Failed to read YubiKey"
        return 1
    fi
    
    cert_hash=$(openssl x509 -in /tmp/verify_cert.pem -outform DER | sha256sum | cut -d' ' -f1)
    admin_cert_hash="$cert_hash"  # Export for use
    
    # Check if authorized
    authorized=$(sqlite3 "$DB_NAME" "SELECT role FROM admin_auth 
                                    WHERE yubikey_cert_hash = '$cert_hash';")
    
    if [[ -n "$authorized" ]]; then
        # Update last auth
        sqlite3 "$DB_NAME" "UPDATE admin_auth SET last_auth = $(date +%s) 
                           WHERE yubikey_cert_hash = '$cert_hash';"
        rm -f /tmp/verify_cert.pem
        return 0
    else
        echo "Unauthorized YubiKey"
        rm -f /tmp/verify_cert.pem
        return 1
    fi
}

authorize_spending() {
    local action="$1"
    local amount="$2"
    
    # Check action permissions
    perms=$(sqlite3 "$DB_NAME" "SELECT require_yubikey, max_amount, daily_limit 
                                FROM action_permissions WHERE action = '$action';")
    
    if [[ -z "$perms" ]]; then
        echo "Unknown action: $action"
        return 1
    fi
    
    IFS='|' read -r require_yubikey max_amount daily_limit <<< "$perms"
    
    # Check if YubiKey required
    if [[ "$require_yubikey" == "1" ]]; then
        if ! verify_admin_yubikey; then
            echo "YubiKey authorization required"
            return 1
        fi
    fi
    
    # Check amount limits
    if (( $(echo "$amount > $max_amount" | bc -l) )); then
        echo "Amount exceeds maximum: $max_amount EMC"
        return 1
    fi
    
    # Check daily spent
    today_start=$(date -d "today 00:00:00" +%s)
    daily_spent=$(sqlite3 "$DB_NAME" "SELECT COALESCE(SUM(amount), 0) 
                                      FROM transaction_log 
                                      WHERE action = '$action' 
                                        AND timestamp >= $today_start 
                                        AND status = 'completed';")
    
    if (( $(echo "$daily_spent + $amount > $daily_limit" | bc -l) )); then
        echo "Would exceed daily limit: $daily_limit EMC"
        echo "Already spent today: $daily_spent EMC"
        return 1
    fi
    
    # Check wallet balance
    wallet_balance=$(emercoin-cli getbalance 2>/dev/null || echo "0")
    
    if (( $(echo "$wallet_balance < $amount" | bc -l) )); then
        echo "Insufficient wallet balance: $wallet_balance EMC"
        return 1
    fi
    
    echo "Transaction authorized"
    echo "  Amount: $amount EMC"
    echo "  Balance: $wallet_balance EMC"
    echo "  Daily spent: $daily_spent EMC"
    
    return 0
}

execute_blockchain_transaction() {
    local name="$1"
    local value="$2"
    local days="${3:-365}"
    local amount="${4:-1.0}"
    
    echo "=== Execute Blockchain Transaction ==="
    
    # Authorize spending
    if ! authorize_spending "blockchain_post" "$amount"; then
        echo "Transaction not authorized"
        return 1
    fi
    
    # Get balance before
    balance_before=$(emercoin-cli getbalance 2>/dev/null || echo "0")
    
    # Execute transaction
    echo "Posting to blockchain..."
    if emercoin-cli name_new "$name" "$value" "$days"; then
        status="completed"
        balance_after=$(emercoin-cli getbalance 2>/dev/null || echo "0")
        echo "Transaction successful"
    else
        status="failed"
        balance_after="$balance_before"
        echo "Transaction failed"
    fi
    
    # Log transaction
    details="{\"name\": \"$name\", \"days\": $days}"
    sqlite3 "$DB_NAME" "INSERT INTO transaction_log 
                       (timestamp, action, amount, balance_before, balance_after, 
                        authorized_by, status, details)
                       VALUES ($(date +%s), 'blockchain_post', $amount, 
                               $balance_before, $balance_after, 
                               '${admin_cert_hash:-system}', '$status', '$details');"
    
    echo "New balance: $balance_after EMC"
}

show_spending_limits() {
    echo "=== Current Spending Limits ==="
    
    sqlite3 "$DB_NAME" -header -column "
        SELECT action, 
               require_yubikey as yubikey,
               max_amount as max_tx,
               daily_limit
        FROM action_permissions;"
}

show_transaction_log() {
    echo "=== Recent Transactions ==="
    
    sqlite3 "$DB_NAME" -header -column "
        SELECT datetime(timestamp, 'unixepoch') as time,
               action,
               amount,
               status,
               balance_after as balance
        FROM transaction_log
        ORDER BY timestamp DESC
        LIMIT 20;"
}

spending_summary() {
    echo "=== Spending Summary ==="
    
    # Today's spending
    today_start=$(date -d "today 00:00:00" +%s)
    today_spent=$(sqlite3 "$DB_NAME" "SELECT COALESCE(SUM(amount), 0) 
                                      FROM transaction_log 
                                      WHERE timestamp >= $today_start 
                                        AND status = 'completed';")
    
    # Current balance
    wallet_balance=$(emercoin-cli getbalance 2>/dev/null || echo "0")
    
    echo "Current balance: $wallet_balance EMC"
    echo "Spent today: $today_spent EMC"
    
    # Spending by action
    echo ""
    echo "Today's spending by action:"
    sqlite3 "$DB_NAME" -header -column "
        SELECT action,
               COUNT(*) as count,
               SUM(amount) as total
        FROM transaction_log
        WHERE timestamp >= $today_start
          AND status = 'completed'
        GROUP BY action;"
}

# Enhanced publish function with spending controls
publish_to_emercoin_secure() {
    local domain="$1"
    local cid="$2"
    local merkle_root="$3"
    local ygg_addr="$4"
    
    # Estimate cost based on data size
    data_size=${#cid}+${#merkle_root}+${#ygg_addr}
    estimated_cost=$(echo "scale=4; 0.01 + ($data_size * 0.00001)" | bc)
    
    echo "Estimated blockchain cost: $estimated_cost EMC"
    echo -n "Proceed with YubiKey authorization? (y/n): "
    read proceed
    
    if [[ "$proceed" != "y" ]]; then
        return 0
    fi
    
    # Build value JSON
    value_json=$(jq -n \
        --arg cid "$cid" \
        --arg merkle "$merkle_root" \
        --arg ygg "$ygg_addr" \
        '{brunnen_g: {cid: $cid, merkle_root: $merkle, yggdrasil: $ygg}}')
    
    # Execute with spending controls
    execute_blockchain_transaction "dns:$domain" "$value_json" 365 "$estimated_cost"
}

# Admin menu
admin_menu() {
    echo "=== Admin Controls ==="
    echo "1) Initial setup"
    echo "2) Configure spending limits"
    echo "3) View spending limits"
    echo "4) Transaction log"
    echo "5) Spending summary"
    echo "6) Add admin"
    echo "7) Admin verification"
    echo -n "Choice: "
    read choice
    
    case $choice in
        1) init_admin_setup ;;
        2) configure_spending_limits ;;
        3) show_spending_limits ;;
        4) show_transaction_log ;;
        5) spending_summary ;;
        6) 
            echo -n "New admin name: "
            read admin_name
            add_admin_yubikey "$admin_name"
            ;;
        7) verify_admin_status ;;
    esac
}

add_admin_yubikey() {
    local admin_name="$1"
    
    # Verify current admin
    if ! verify_admin_yubikey; then
        echo "Admin authentication required"
        return 1
    fi
    
    echo "Insert new admin's YubiKey and press Enter..."
    read
    
    if ! ykman piv certificates export 9a /tmp/new_admin.pem; then
        echo "Failed to read YubiKey"
        return 1
    fi
    
    new_cert_hash=$(openssl x509 -in /tmp/new_admin.pem -outform DER | sha256sum | cut -d' ' -f1)
    
    sqlite3 "$DB_NAME" "INSERT OR IGNORE INTO admin_auth 
                       (yubikey_cert_hash, role, created_at, created_by)
                       VALUES ('$new_cert_hash', 'admin', $(date +%s), '$admin_cert_hash');"
    
    echo "Added admin: $admin_name"
    rm -f /tmp/new_admin.pem
}

configure_domain_whitelist() {
    echo -n "Domain: "
    read domain
    
    echo -n "Enable whitelist mode? (y/n): "
    read enable
    
    sqlite3 "$DB_NAME" "INSERT OR REPLACE INTO domain_policies 
                       (domain, whitelist_mode) 
                       VALUES ('$domain', $([ "$enable" = "y" ] && echo 1 || echo 0));"
}

add_to_whitelist() {
    echo -n "Domain: "
    read domain
    echo -n "Yggdrasil pubkey to allow: "
    read ygg_key
    
    sqlite3 "$DB_NAME" "INSERT INTO domain_whitelists 
                       (domain, ygg_pubkey, added_by, added_at)
                       VALUES ('$domain', '$ygg_key', 'admin', $(date +%s));"
}

# Parse command line arguments
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
DOMAIN_VERIFIED_FILE="/tmp/.brunnen_domain_verified"
DOMAIN_VERIFY_LOCK="/tmp/.brunnen_domain.lock"

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
    # Ensure data directory exists
    mkdir -p ./data
    
    sqlite3 $DB_NAME "
    CREATE TABLE IF NOT EXISTS address_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL,
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
        domain TEXT NOT NULL,
        TPM_enable BOOLEAN DEFAULT 1,
        row_hash BLOB
    );
    
    CREATE TABLE IF NOT EXISTS domain_settings (
        domain TEXT PRIMARY KEY,
        owner_address TEXT,
        verified_at INTEGER
    );
    
    CREATE TABLE IF NOT EXISTS api_keys (
        app_name TEXT PRIMARY KEY,
        api_key TEXT NOT NULL,
        permissions TEXT DEFAULT 'read',
        created_at INTEGER,
        last_used INTEGER
    );
    "
    echo "Database created: $DB_NAME"
}

verify_domain_ownership() {
    local domain=$1
    
    # Initialize domain_address as empty
    domain_address=""
    
    # Use lock file to prevent concurrent verification
    (
        flock -x 200
        
        # Check if already verified recently (24 hours)
        if [[ -f "$DOMAIN_VERIFIED_FILE" ]]; then
            local last_verify=$(stat -c %Y "$DOMAIN_VERIFIED_FILE" 2>/dev/null || echo 0)
            local current_time=$(date +%s)
            if [[ $((current_time - last_verify)) -lt 86400 ]]; then
                # Read cached info
                local cached_info=$(cat "$DOMAIN_VERIFIED_FILE")
                domain_address=$(echo "$cached_info" | cut -d'|' -f2)
                echo "Domain already verified: $domain (cached)"
                echo "Owner address: $domain_address"
                # Write to temp file for persistence outside lock
                echo "$domain_address" > /tmp/.brunnen_domain_address_tmp
            else
                # Verify from blockchain
                domain_info=$(emercoin-cli name_show "dns:$domain" 2>&1)
                if [[ $? -ne 0 ]]; then
                    echo "Domain not found on blockchain"
                    return 1
                fi
                
                # Extract owner address
                domain_address=$(echo "$domain_info" | jq -r '.address // empty')
                if [[ -z "$domain_address" ]]; then
                    echo "Could not extract domain address"
                    return 1
                fi
                
                echo "Domain found: $domain"
                echo "Owner address: $domain_address"
                
                # Store in database
                sqlite3 "$DB_NAME" "
                    INSERT OR REPLACE INTO domain_settings (domain, owner_address, verified_at)
                    VALUES ('$domain', '$domain_address', $(date +%s));
                "
                
                # Cache verification
                echo "$domain|$domain_address" > "$DOMAIN_VERIFIED_FILE"
                
                # Write to temp file for persistence outside lock
                echo "$domain_address" > /tmp/.brunnen_domain_address_tmp
            fi
        else
            # First time verification
            domain_info=$(emercoin-cli name_show "dns:$domain" 2>&1)
            if [[ $? -ne 0 ]]; then
                echo "Domain not found on blockchain"
                return 1
            fi
            
            # Extract owner address
            domain_address=$(echo "$domain_info" | jq -r '.address // empty')
            if [[ -z "$domain_address" ]]; then
                echo "Could not extract domain address"
                return 1
            fi
            
            echo "Domain found: $domain"
            echo "Owner address: $domain_address"
            
            # Store in database
            sqlite3 "$DB_NAME" "
                INSERT OR REPLACE INTO domain_settings (domain, owner_address, verified_at)
                VALUES ('$domain', '$domain_address', $(date +%s));
            "
            
            # Cache verification
            echo "$domain|$domain_address" > "$DOMAIN_VERIFIED_FILE"
            
            # Write to temp file for persistence outside lock
            echo "$domain_address" > /tmp/.brunnen_domain_address_tmp
        fi
        
    ) 200>"$DOMAIN_VERIFY_LOCK"
    
    # Read domain_address from temp file
    if [[ -f /tmp/.brunnen_domain_address_tmp ]]; then
        domain_address=$(cat /tmp/.brunnen_domain_address_tmp)
        rm -f /tmp/.brunnen_domain_address_tmp
    fi
    
    # Verify domain_address is set
    if [[ -z "$domain_address" ]]; then
        echo "Failed to get domain address"
        return 1
    fi
    
    # Set as global export
    export domain_address
    
    # Continue with wallet selection
    wallets=$(emercoin-cli listwallets | jq -r '.[]')
    echo "Available wallets:"
    IFS=$'\n' read -rd '' -a wallet_array <<< "$wallets"
    
    for i in "${!wallet_array[@]}"; do
        echo "$((i+1))) ${wallet_array[i]}"
    done
    
    echo -n "Select wallet: "
    read wallet_choice
    selected_wallet="${wallet_array[$((wallet_choice-1))]}"
    export selected_wallet
    
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
    if [[ $? -eq 0 ]]; then
        echo "Domain ownership verified"
        return 0
    else
        echo "Signature failed"
        return 1
    fi
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
        "domain_settings")
            row_data=$(sqlite3 "$DB_NAME" "SELECT domain || '|' || COALESCE(owner_address,'') || '|' || COALESCE(verified_at,0) FROM domain_settings WHERE domain = '$id'")
            row_hash=$(echo -n "$row_data" | sha256sum | cut -d' ' -f1)
            # Note: domain_settings uses domain as primary key, not id
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
    
    # Update address_keys
    sqlite3 "$DB_NAME" "SELECT id FROM address_keys;" | while read id; do
        calculate_row_hash "address_keys" "$id"
    done
    
    # Update tpm_domain_settings
    sqlite3 "$DB_NAME" "SELECT id FROM tpm_domain_settings;" | while read id; do
        calculate_row_hash "tpm_domain_settings" "$id"
    done
    
    # Update domain_settings (uses domain as key)
    sqlite3 "$DB_NAME" "SELECT domain FROM domain_settings;" | while read domain; do
        calculate_row_hash "domain_settings" "$domain"
    done
    
    # Build merkle roots for each table
    build_table_merkle "address_keys"
    build_table_merkle "tpm_domain_settings"
    build_table_merkle "domain_settings"
    
    # Update db_root hashes
    sqlite3 "$DB_NAME" "SELECT id FROM db_root;" | while read id; do 
         calculate_row_hash "db_root" "$id"
    done

    # Final root of roots
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

generate_yubikey_cert() {
    local address="$1"
    local tpm_handle="$2"
    
    echo "Generating YubiKey certificate tied to TPM..."
    
    # Create unique temp files with proper permissions
    local temp_id="$$"
    local tpm_pub_file="/dev/shm/tpm_pub_${temp_id}.pem"
    local yubikey_pub_file="/dev/shm/yubikey_pub_${temp_id}.pem"
    local linked_cert_file="/dev/shm/linked_cert_${temp_id}.pem"
    
    # Ensure clean state
    rm -f "$tpm_pub_file" "$yubikey_pub_file" "$linked_cert_file" 2>/dev/null
    
    # Export TPM public key with proper permissions
    if check_tpm_access; then
        tpm2_readpublic -c "$tpm_handle" -f pem -o "$tpm_pub_file"
    else
        sudo tpm2_readpublic -c "$tpm_handle" -f pem -o "$tpm_pub_file"
        # Fix ownership after sudo operation
        sudo chown $(whoami):$(id -gn) "$tpm_pub_file"
    fi
    chmod 644 "$tpm_pub_file"
    
    # Generate YubiKey key with proper file handling
    touch "$yubikey_pub_file"
    chmod 666 "$yubikey_pub_file"
    
    if ! ykman piv keys generate 9a "$yubikey_pub_file" 2>/dev/null; then
        echo "Retrying YubiKey key generation..."
        # Sometimes YubiKey needs a reset
        ykman piv reset 2>/dev/null || true
        sleep 1
        ykman piv keys generate 9a "$yubikey_pub_file"
    fi
    
    # Ensure file is readable
    chmod 644 "$yubikey_pub_file"
    
    # Generate self-signed certificate using the YubiKey public key
    # Since we can't use TPM private key directly, we create a cert request instead
    openssl req -new -x509 -days 365 \
        -key <(ykman piv keys export 9a) \
        -out "$linked_cert_file" \
        -subj "/CN=$address/O=Brunnen-G/OU=TPM-YubiKey" 2>/dev/null || \
    # Fallback: create a simple self-signed cert
    openssl req -new -x509 -days 365 \
        -nodes -keyout /dev/shm/temp_key_${temp_id}.pem \
        -out "$linked_cert_file" \
        -subj "/CN=$address/O=Brunnen-G/OU=TPM-YubiKey"
    
    # Import certificate to YubiKey
    if [[ -f "$linked_cert_file" ]]; then
        ykman piv certificates import 9a "$linked_cert_file"
        
        # Calculate combined hash
        if [[ -f "$tpm_pub_file" ]] && [[ -f "$yubikey_pub_file" ]]; then
            combined_hash=$(cat "$tpm_pub_file" "$yubikey_pub_file" | sha256sum | cut -d' ' -f1)
            echo "YubiKey cert installed. Combined hash: $combined_hash"
            
            # Update database
            sqlite3 "$DB_NAME" "UPDATE address_keys SET yubikey_hash = '$combined_hash' WHERE address = '$address';"
        else
            echo "Warning: Could not calculate combined hash"
        fi
    else
        echo "Error: Failed to generate certificate"
        return 1
    fi
    
    # Cleanup
    shred -u "$tpm_pub_file" "$yubikey_pub_file" "$linked_cert_file" "/dev/shm/temp_key_${temp_id}.pem" 2>/dev/null || \
    rm -f "$tpm_pub_file" "$yubikey_pub_file" "$linked_cert_file" "/dev/shm/temp_key_${temp_id}.pem" 2>/dev/null
    
    return 0
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
    
    shred -u /dev/shm/yubikey_cert.pem /dev/shm/yubikey_pub.pem /dev/shm/remote_db 2>/dev/null || true
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
    
    # Ensure tpmdata directory exists
    mkdir -p ./tpmdata
    
    # Create or update provisioning.json
    if [[ -f "./tpmdata/provisioning.json" ]]; then
        # First decrypt if encrypted
        if [[ -f "./tpmdata/provisioning.enc" ]]; then
            if ! decrypt_metadata 2>/dev/null; then
                echo "Creating new metadata file"
                echo '{"identities":{},"domain_settings":{},"version":"2.0"}' > ./tpmdata/provisioning.json
            fi
        fi
        
        # Update existing file
        jq --arg addr "$address" --arg handle "$tmp_handle" \
           '.identities[$addr] = {
               "tmp_handle": $handle,
               "created_at": (now | tostring),
               "encryption_method": "yubikey_aes"
           }' ./tpmdata/provisioning.json > /dev/shm/provisioning_new.json
        
        # Check if jq succeeded
        if [[ $? -eq 0 ]] && [[ -s /dev/shm/provisioning_new.json ]]; then
            mv /dev/shm/provisioning_new.json ./tpmdata/provisioning.json
        else
            echo "Failed to update metadata, creating new file"
            jq -n --arg addr "$address" --arg handle "$tmp_handle" \
               '{
                   "identities": {
                       ($addr): {
                           "tmp_handle": $handle,
                           "created_at": (now | tostring),
                           "encryption_method": "yubikey_aes"
                       }
                   },
                   "domain_settings": {},
                   "version": "2.0"
               }' > ./tpmdata/provisioning.json
        fi
    else
        # Create new file
        jq -n --arg addr "$address" --arg handle "$tmp_handle" \
           '{
               "identities": {
                   ($addr): {
                       "tmp_handle": $handle,
                       "created_at": (now | tostring),
                       "encryption_method": "yubikey_aes"
                   }
               },
               "domain_settings": {},
               "version": "2.0"
           }' > ./tpmdata/provisioning.json
    fi
    
    # Copy to shm for encryption
    cp ./tpmdata/provisioning.json /dev/shm/provisioning.json
    
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

encrypt_metadata() {
    if [[ ! -f "/dev/shm/provisioning.json" ]]; then
        if [[ -f "./tpmdata/provisioning.json" ]]; then
            cp ./tpmdata/provisioning.json /dev/shm/provisioning.json
        else
            echo "No metadata to encrypt"
            return 1
        fi
    fi
    
    # Check if YubiKey is available
    if ! command -v ykchalresp >/dev/null; then
        echo "YubiKey tools not installed"
        return 1
    fi
    
    # Check if YubiKey is connected
    if ! ykchalresp -2 -x "00" >/dev/null 2>&1; then
        echo "YubiKey not detected"
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
        # Data unchanged, check for existing challenge
        if [[ -f /dev/shm/.brunnen_challenge ]]; then
            challenge=$(cat /dev/shm/.brunnen_challenge)
            echo "Reusing existing challenge"
        else
            # No challenge exists, generate new one
            challenge=$(openssl rand 32 | xxd -p -c 32)
            echo "$challenge" > /dev/shm/.brunnen_challenge
            echo "Generated new challenge"
        fi
    fi
    
    # Get AES key from YubiKey
    aes_key=$(ykchalresp -2 -x "$challenge" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "Failed to get response from YubiKey"
        return 1
    fi
    
    # Encrypt the metadata
    openssl enc -aes-256-cbc -in /dev/shm/provisioning.json \
        -out ./tpmdata/provisioning.enc -k "$aes_key" -pbkdf2
    
    if [[ $? -eq 0 ]]; then
        chmod 600 ./tpmdata/provisioning.enc /dev/shm/.brunnen_challenge
        shred -u /dev/shm/provisioning.json 2>/dev/null || rm -f /dev/shm/provisioning.json
        echo "Metadata encrypted with YubiKey"
        return 0
    else
        echo "Encryption failed"
        return 1
    fi
}

decrypt_metadata() {
    if [[ ! -f "./tpmdata/provisioning.enc" ]]; then
        echo "No encrypted metadata found"
        return 1
    fi
    
    # Check if YubiKey is available
    if ! command -v ykchalresp >/dev/null; then
        echo "YubiKey tools not installed"
        return 1
    fi
    
    # Check if YubiKey is connected
    if ! ykchalresp -2 -x "00" >/dev/null 2>&1; then
        echo "YubiKey not detected"
        return 1
    fi
    
    # Ensure tpmdata directory exists and is writable
    if [[ ! -w "./tpmdata" ]]; then
        echo "Cannot write to ./tpmdata directory"
        return 1
    fi
    
    # Check for challenge file
    if [[ ! -f "/dev/shm/.brunnen_challenge" ]]; then
        echo "No challenge found - metadata may have been encrypted on another system"
        return 1
    fi
    
    challenge=$(cat /dev/shm/.brunnen_challenge)
    aes_key=$(ykchalresp -2 -x "$challenge" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo "Failed to get response from YubiKey"
        return 1
    fi
    
    # Decrypt the metadata
    openssl enc -aes-256-cbc -d -in ./tpmdata/provisioning.enc \
        -out /dev/shm/provisioning.json -k "$aes_key" -pbkdf2
    
    if [[ $? -eq 0 ]]; then
        echo "Metadata decrypted"
        return 0
    else
        echo "Decryption failed - wrong YubiKey or corrupted data?"
        return 1
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
    
    export BRUNNEN_DOMAIN="$domain"

    if ! verify_domain_ownership "$domain"; then
        echo "Domain ownership verification failed"
        return 1
    fi
    
    address="${username}@${domain}"
    
    # Check for existing encrypted metadata using your existing decrypt function
    if [[ -f "./tpmdata/provisioning.enc" ]]; then
        if [[ "$HACKER_MODE" == "1" ]]; then
            echo -e "\033[37mmetadata.exists:\033[0m checking identity..."
        else
            echo "Found existing encrypted metadata, checking for identity..."
        fi
        
        # Try to decrypt existing metadata using existing function
        if decrypt_metadata 2>/dev/null; then
            EXISTING_HANDLE=$(jq -r ".identities[\"$address\"].tmp_handle // empty" /dev/shm/provisioning.json 2>/dev/null)
            
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
                    tpm2_readpublic -c "$tmp_handle" -f der -o /dev/shm/tmp_pub.der
                    tmp_pubkey=$(xxd -p -c 256 < /dev/shm/tmp_pub.der)
                    shred -u /dev/shm/tmp_pub.der
                    
                    create_database
                    sqlite3 "$DB_NAME" "INSERT OR REPLACE INTO address_keys (address, pubkey, TPM_key, TPM_enable, yubikey_hash) 
                                       VALUES ('$address', '$tmp_pubkey', '$tmp_handle', 1, '');"
                    if ! sqlite3 "$DB_NAME" "INSERT OR REPLACE INTO address_keys..."; then
                        echo "Database insert failed: $?"
                    fi
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
        shred -u /dev/shm/sign_data /dev/shm/signature 2>/dev/null || true
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
    
    shred -u /dev/shm/verify_data /dev/shm/verify_sig 2>/dev/null || true
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
    if command -v yggdrasilctl >/dev/null 2>&1; then
        yggdrasilctl getSelf 2>/dev/null | grep -oE '200:[a-f0-9:]+' || echo ""
    else
        echo ""
    fi
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

configure_voip() {
    echo "=== Configure VoIP ==="
    
    # Check if Asterisk is installed
    if ! command -v asterisk >/dev/null; then
        echo "Asterisk not installed. Install with: sudo apt-get install asterisk"
        return 1
    fi
    
    echo -n "Your Brunnen-G identity (user@domain): "
    read identity
    
    # Extract user and domain
    user="${identity%@*}"
    domain="${identity#*@}"
    
    # Generate SIP configuration
    cat > /tmp/brunnen_sip.conf <<EOF
[brunnen-${user}]
type=friend
context=brunnen-g
host=dynamic
secret=$(openssl rand -hex 16)
dtmfmode=rfc2833
canreinvite=no
nat=yes
qualify=yes
callerid="${user}@${domain}"
EOF
    
    echo "SIP configuration generated at /tmp/brunnen_sip.conf"
    echo "Add this to /etc/asterisk/sip.conf and reload Asterisk"
    
    # Generate dialplan
    cat > /tmp/brunnen_dialplan.conf <<EOF
[brunnen-g]
; Dial Brunnen-G identities
exten => _[a-zA-Z0-9].,1,NoOp(Dialing Brunnen-G identity \${EXTEN})
same => n,Set(IDENTITY=\${EXTEN})
same => n,AGI(brunnen_lookup.agi,\${IDENTITY})
same => n,Dial(SIP/\${SIPURI},30)
same => n,Hangup()
EOF
    
    echo "Dialplan generated at /tmp/brunnen_dialplan.conf"
    echo "Add this to /etc/asterisk/extensions.conf"
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
        shred -u /dev/shm/api_sign_data /dev/shm/api_signature 2>/dev/null || true
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
        shred -u /dev/shm/api_verify_data /dev/shm/api_verify_sig 2>/dev/null || true
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
   local pid_file="/tmp/brunnen_api.pid"
   
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

quick_setup() {
    echo "=== Quick Setup ==="
    start_yggdrasil
    register_identity
    start_api_daemon
    echo "Setup complete! Your identity is registered and services are running."
}

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
    echo -n "Choice: "
    read choice
    
    case $choice in
        1) query_user ;;
        2) sign_data ;;
        3) verify_signature ;;
        *) echo "Invalid choice" ;;
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
    fi
    echo -n "Choice: "
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
        echo -e "\033[32m3) tpm\033[0m.\033[37mmaintenance\033[0m"
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
        3) tpm_maintenance ;;
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

tpm_maintenance() {
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
        1) tpm2_getcap handles-persistent ;;
        2) encrypt_metadata ;;
        3) decrypt_metadata ;;
        4) run_tpm_script ./tpm/tpm_provisioning.sh ;;
    esac
}

# Initialize Brunnen-G environment
initialize_brunnen() {
    # Create necessary directories
    mkdir -p ./data ./tpmdata
    
    # Check for existing database
    if [[ ! -f "$DB_NAME" ]]; then
        echo "Initializing Brunnen-G database..."
        create_database
    fi
    
    # Quick dependency check (silent)
    local missing_deps=()
    command -v tpm2_getcap >/dev/null || missing_deps+=("tpm2-tools")
    command -v ykchalresp >/dev/null || missing_deps+=("yubikey-manager")
    command -v ipfs >/dev/null || missing_deps+=("ipfs")
    command -v emercoin-cli >/dev/null || missing_deps+=("emercoin")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo "Note: Some optional dependencies missing: ${missing_deps[*]}"
        echo "Run with --check-deps for details"
    fi
}

# Display banner
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

# Initialize system
initialize_brunnen

# Main menu loop
# Color codes for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

display_banner() {
    clear
    echo -e "${CYAN}"
    echo " ██████╗ ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗███╗   ██╗       ██████╗ "
    echo " ██╔══██╗██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝████╗  ██║      ██╔════╝ "
    echo " ██████╔╝██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██╔██╗ ██║█████╗██║  ███╗"
    echo " ██╔══██╗██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║╚██╗██║╚════╝██║   ██║"
    echo " ██████╔╝██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║ ╚████║      ╚██████╔╝"
    echo " ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝       ╚═════╝ "
    echo -e "${WHITE}                     [[ DECENTRALIZED PKI INFRASTRUCTURE ]]${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

display_status() {
    echo -e "${YELLOW}[SYSTEM STATUS]${NC}"
    
    # Yggdrasil status
    if pgrep yggdrasil >/dev/null; then
        local ygg_addr=$(yggdrasilctl getSelf 2>/dev/null | grep -oE '200:[a-f0-9:]+' || echo "UNKNOWN")
        echo -e " ${GREEN}●${NC} Yggdrasil: ${GREEN}ONLINE${NC} [$ygg_addr]"
    else
        echo -e " ${RED}●${NC} Yggdrasil: ${RED}OFFLINE${NC}"
    fi
    
    # API status
    if pgrep -f "api_daemon.py" >/dev/null; then
        echo -e " ${GREEN}●${NC} API Daemon: ${GREEN}ONLINE${NC} [Port $API_PORT]"
    else
        echo -e " ${RED}●${NC} API Daemon: ${RED}OFFLINE${NC}"
    fi
    
    # Database status
    if [[ -f "$DB_NAME" ]]; then
        local db_size=$(du -h "$DB_NAME" | cut -f1)
        local user_count=$(sqlite3 "$DB_NAME" "SELECT COUNT(*) FROM address_keys;" 2>/dev/null || echo "0")
        echo -e " ${GREEN}●${NC} Database: ${GREEN}ACTIVE${NC} [Size: $db_size | Users: $user_count]"
    else
        echo -e " ${RED}●${NC} Database: ${RED}NOT INITIALIZED${NC}"
    fi
    
    # Admin setup status
    if [[ -f "${DB_NAME}.setup" ]]; then
        echo -e " ${GREEN}●${NC} Admin Setup: ${GREEN}COMPLETE${NC}"
    else
        echo -e " ${YELLOW}●${NC} Admin Setup: ${YELLOW}PENDING${NC}"
    fi
    
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

main_menu() {
    while true; do
        display_banner
        display_status
        
        echo -e "${CYAN}[MAIN MENU]${NC}"
        echo -e "${WHITE} 1)${NC} Identity Management      ${PURPLE}[Register/Query/Verify]${NC}"
        echo -e "${WHITE} 2)${NC} Security & Access       ${PURPLE}[Registration Controls/YubiKey]${NC}"
        echo -e "${WHITE} 3)${NC} Network Operations      ${PURPLE}[Yggdrasil/API/P2P]${NC}"
        echo -e "${WHITE} 4)${NC} Blockchain Operations   ${PURPLE}[Emercoin/IPFS/Storage]${NC}"
        echo -e "${WHITE} 5)${NC} Administration          ${PURPLE}[Setup/Spending/Logs]${NC}"
        echo -e "${WHITE} 6)${NC} Quick Actions           ${PURPLE}[Common Tasks]${NC}"
        echo -e "${WHITE} 0)${NC} Exit"
        echo ""
        echo -ne "${GREEN}brunnen-g>${NC} "
        
        read -r choice
        case $choice in
            1) identity_menu ;;
            2) security_menu ;;
            3) network_menu ;;
            4) blockchain_menu ;;
            5) admin_menu_enhanced ;;
            6) quick_actions_menu ;;
            0) shutdown_services; exit 0 ;;
            *) echo -e "${RED}[!] Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

identity_menu() {
    while true; do
        display_banner
        echo -e "${CYAN}[IDENTITY MANAGEMENT]${NC}"
        echo -e "${WHITE} 1)${NC} Register Identity       ${PURPLE}[Create new user@domain.coin]${NC}"
        echo -e "${WHITE} 2)${NC} Query User             ${PURPLE}[Lookup public key]${NC}"
        echo -e "${WHITE} 3)${NC} Verify Identity        ${PURPLE}[Check authenticity]${NC}"
        echo -e "${WHITE} 4)${NC} Sign Data              ${PURPLE}[TPM signature]${NC}"
        echo -e "${WHITE} 5)${NC} Verify Signature       ${PURPLE}[Check TPM signature]${NC}"
        echo -e "${WHITE} 6)${NC} YubiKey Operations     ${PURPLE}[Physical key management]${NC}"
        echo -e "${WHITE} 0)${NC} Back"
        echo ""
        echo -ne "${GREEN}identity>${NC} "
        
        read -r choice
        case $choice in
            1) enhanced_register_identity ;;
            2) query_user ;;
            3) verify_identity ;;
            4) sign_data ;;
            5) verify_signature ;;
            6) yubikey_menu ;;
            0) return ;;
            *) echo -e "${RED}[!] Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

security_menu() {
    while true; do
        display_banner
        echo -e "${CYAN}[SECURITY & ACCESS CONTROL]${NC}"
        echo -e "${WHITE} 1)${NC} Configure Domain       ${PURPLE}[Set registration rules]${NC}"
        echo -e "${WHITE} 2)${NC} Manage Approvers       ${PURPLE}[Add/remove YubiKey admins]${NC}"
        echo -e "${WHITE} 3)${NC} Pending Registrations  ${PURPLE}[Review queue]${NC}"
        echo -e "${WHITE} 4)${NC} Approve Registration   ${PURPLE}[Authorize new users]${NC}"
        echo -e "${WHITE} 5)${NC} Registration Stats     ${PURPLE}[View metrics]${NC}"
        echo -e "${WHITE} 6)${NC} API Key Management     ${PURPLE}[Create/revoke keys]${NC}"
        echo -e "${WHITE} 0)${NC} Back"
        echo ""
        echo -ne "${GREEN}security>${NC} "
        
        read -r choice
        case $choice in
            1) configure_domain_security ;;
            2) manage_approvers ;;
            3) list_pending_registrations ;;
            4) approve_registration ;;
            5) show_registration_stats ;;
            6) api_key_menu ;;
            0) return ;;
            *) echo -e "${RED}[!] Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

network_menu() {
    while true; do
        display_banner
        echo -e "${CYAN}[NETWORK OPERATIONS]${NC}"
        echo -e "${WHITE} 1)${NC} Start Yggdrasil        ${PURPLE}[TPM-secured mesh network]${NC}"
        echo -e "${WHITE} 2)${NC} Stop Yggdrasil         ${PURPLE}[Shutdown mesh network]${NC}"
        echo -e "${WHITE} 3)${NC} Start API Daemon       ${PURPLE}[Enable REST API]${NC}"
        echo -e "${WHITE} 4)${NC} Stop API Daemon        ${PURPLE}[Disable REST API]${NC}"
        echo -e "${WHITE} 5)${NC} Network Status         ${PURPLE}[Show connections]${NC}"
        echo -e "${WHITE} 6)${NC} Sync with Peers        ${PURPLE}[P2P synchronization]${NC}"
        echo -e "${WHITE} 0)${NC} Back"
        echo ""
        echo -ne "${GREEN}network>${NC} "
        
        read -r choice
        case $choice in
            1) start_yggdrasil ;;
            2) stop_yggdrasil ;;
            3) start_api_daemon ;;
            4) stop_api_daemon ;;
            5) show_network_status ;;
            6) sync_with_peers ;;
            0) return ;;
            *) echo -e "${RED}[!] Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

blockchain_menu() {
    while true; do
        display_banner
        echo -e "${CYAN}[BLOCKCHAIN OPERATIONS]${NC}"
        echo -e "${WHITE} 1)${NC} Publish to Blockchain  ${PURPLE}[Emercoin NVS]${NC}"
        echo -e "${WHITE} 2)${NC} IPFS Operations        ${PURPLE}[Pin/unpin files]${NC}"
        echo -e "${WHITE} 3)${NC} Download Database      ${PURPLE}[From remote domain]${NC}"
        echo -e "${WHITE} 4)${NC} Update Merkle Roots    ${PURPLE}[Rehash database]${NC}"
        echo -e "${WHITE} 5)${NC} Storage Tiering        ${PURPLE}[CBOR/IPFS/BitTorrent]${NC}"
        echo -e "${WHITE} 0)${NC} Back"
        echo ""
        echo -ne "${GREEN}blockchain>${NC} "
        
        read -r choice
        case $choice in
            1) 
                echo -n "Enter domain: "
                read domain
                cid=$(publish_database_ipfs)
                merkle_root=$(sqlite3 "$DB_NAME" "SELECT root FROM db_root WHERE table_name='db_root';")
                publish_to_emercoin_secure "$domain" "$cid" "$merkle_root" "$(get_yggdrasil_address)"
                ;;
            2) ipfs_menu ;;
            3) 
                echo -n "Remote domain: "
                read domain
                download_remote_database "$domain"
                ;;
            4) update_all_merkle_roots ;;
            5) storage_menu ;;
            0) return ;;
            *) echo -e "${RED}[!] Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

admin_menu_enhanced() {
    while true; do
        display_banner
        echo -e "${CYAN}[ADMINISTRATION]${NC}"
        echo -e "${WHITE} 1)${NC} Initial Setup          ${PURPLE}[One-time configuration]${NC}"
        echo -e "${WHITE} 2)${NC} Spending Controls      ${PURPLE}[Limits & authorization]${NC}"
        echo -e "${WHITE} 3)${NC} Transaction Logs       ${PURPLE}[Audit trail]${NC}"
        echo -e "${WHITE} 4)${NC} Admin Management       ${PURPLE}[Add/remove admins]${NC}"
        echo -e "${WHITE} 5)${NC} Database Maintenance   ${PURPLE}[Backup/restore]${NC}"
        echo -e "${WHITE} 6)${NC} System Diagnostics     ${PURPLE}[Health checks]${NC}"
        echo -e "${WHITE} 0)${NC} Back"
        echo ""
        echo -ne "${GREEN}admin>${NC} "
        
        read -r choice
        case $choice in
            1) init_admin_setup ;;
            2) spending_controls_menu ;;
            3) show_transaction_log ;;
            4) admin_management_menu ;;
            5) database_menu ;;
            6) system_diagnostics ;;
            0) return ;;
            *) echo -e "${RED}[!] Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

quick_actions_menu() {
    while true; do
        display_banner
        echo -e "${CYAN}[QUICK ACTIONS]${NC}"
        echo -e "${WHITE} 1)${NC} Quick Setup            ${PURPLE}[Register + Start all]${NC}"
        echo -e "${WHITE} 2)${NC} Start All Services     ${PURPLE}[Yggdrasil + API]${NC}"
        echo -e "${WHITE} 3)${NC} Stop All Services      ${PURPLE}[Clean shutdown]${NC}"
        echo -e "${WHITE} 4)${NC} Health Check           ${PURPLE}[Verify system]${NC}"
        echo -e "${WHITE} 5)${NC} Emergency Backup       ${PURPLE}[Export critical data]${NC}"
        echo -e "${WHITE} 0)${NC} Back"
        echo ""
        echo -ne "${GREEN}quick>${NC} "
        
        read -r choice
        case $choice in
            1) quick_setup ;;
            2) auto_start ;;
            3) shutdown_services ;;
            4) health_check ;;
            5) emergency_backup ;;
            0) return ;;
            *) echo -e "${RED}[!] Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

# Helper functions
show_network_status() {
    echo -e "${YELLOW}[NETWORK STATUS]${NC}"
    
    if pgrep yggdrasil >/dev/null; then
        echo -e "${GREEN}Yggdrasil peers:${NC}"
        yggdrasilctl getPeers | jq -r '.peers | to_entries[] | "\(.key) - Uptime: \(.value.uptime)s"' 2>/dev/null || echo "No peers"
    else
        echo -e "${RED}Yggdrasil not running${NC}"
    fi
    
    echo ""
    echo "Press Enter to continue..."
    read
}

shutdown_services() {
    echo -e "${YELLOW}[SHUTTING DOWN]${NC}"
    stop_api_daemon
    stop_yggdrasil
    echo -e "${GREEN}[✓] All services stopped${NC}"
    sleep 1
}

health_check() {
    echo -e "${YELLOW}[SYSTEM HEALTH CHECK]${NC}"
    
    # Check TPM
    if tpm2_getcap properties-fixed 2>/dev/null | grep -q TPM; then
        echo -e " ${GREEN}[✓]${NC} TPM: Available"
    else
        echo -e " ${RED}[✗]${NC} TPM: Not available"
    fi
    
    # Check YubiKey
    if ykman list 2>/dev/null | grep -q "YubiKey"; then
        echo -e " ${GREEN}[✓]${NC} YubiKey: Detected"
    else
        echo -e " ${YELLOW}[!]${NC} YubiKey: Not detected"
    fi
    
    # Check Emercoin
    if emercoin-cli getinfo >/dev/null 2>&1; then
        echo -e " ${GREEN}[✓]${NC} Emercoin: Running"
    else
        echo -e " ${RED}[✗]${NC} Emercoin: Not running"
    fi
    
    # Check IPFS
    if ipfs id >/dev/null 2>&1; then
        echo -e " ${GREEN}[✓]${NC} IPFS: Running"
    else
        echo -e " ${YELLOW}[!]${NC} IPFS: Not running"
    fi
    
    echo ""
    echo "Press Enter to continue..."
    read
}

# Start the main menu
main_menu