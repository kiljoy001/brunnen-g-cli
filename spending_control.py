#!/usr/bin/env python3
"""
One-time Admin Setup and Spending Control for Brunnen-G
"""
import os
import json
import time
import sqlite3
import hashlib
import threading
import subprocess
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class AdminSetup:
    def __init__(self, db_path):
        self.db_path = db_path
        self.setup_lock = threading.Lock()
        self.setup_complete = False
        self._check_setup_status()
    
    def _check_setup_status(self):
        """Check if initial setup is complete"""
        if os.path.exists(f"{self.db_path}.setup"):
            self.setup_complete = True
    
    def initialize_admin(self):
        """One-time admin setup with semaphore"""
        with self.setup_lock:
            if self.setup_complete:
                return {"status": "error", "message": "Setup already complete"}
            
            print("=== Initial Admin Setup ===")
            
            # Create admin tables
            self._create_admin_tables()
            
            # Generate master key in TPM
            tpm_handle = self._generate_tpm_master_key()
            
            # Setup first admin with YubiKey
            admin_cert_hash = self._setup_first_admin()
            
            # Configure initial spending limits
            self._configure_initial_limits()
            
            # Mark setup complete
            with open(f"{self.db_path}.setup", "w") as f:
                json.dump({
                    "setup_date": int(time.time()),
                    "tpm_handle": tpm_handle,
                    "admin_cert": admin_cert_hash
                }, f)
            
            self.setup_complete = True
            return {"status": "success", "message": "Admin setup complete"}
    
    def _create_admin_tables(self):
        """Create administrative control tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Admin authentication
                CREATE TABLE IF NOT EXISTS admin_auth (
                    yubikey_cert_hash TEXT PRIMARY KEY,
                    role TEXT DEFAULT 'admin',
                    created_at INTEGER,
                    created_by TEXT,
                    last_auth INTEGER
                );
                
                -- Spending limits (encrypted)
                CREATE TABLE IF NOT EXISTS spending_limits (
                    id INTEGER PRIMARY KEY,
                    encrypted_data BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    updated_at INTEGER,
                    updated_by TEXT
                );
                
                -- Transaction log
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
                
                -- Action permissions
                CREATE TABLE IF NOT EXISTS action_permissions (
                    action TEXT PRIMARY KEY,
                    require_yubikey BOOLEAN DEFAULT 1,
                    max_amount REAL,
                    daily_limit REAL
                );
            """)
    
    def _generate_tpm_master_key(self):
        """Generate master encryption key in TPM"""
        handle = "0x81800000"  # Fixed handle for master key
        
        # Create primary key
        subprocess.run([
            "tpm2_createprimary", "-C", "o", "-g", "sha256", 
            "-G", "aes", "-c", "/tmp/master.ctx"
        ], check=True)
        
        # Make persistent
        subprocess.run([
            "tpm2_evictcontrol", "-C", "o", "-c", "/tmp/master.ctx", handle
        ], check=True)
        
        os.remove("/tmp/master.ctx")
        return handle
    
    def _setup_first_admin(self):
        """Setup first admin with YubiKey"""
        print("Insert admin YubiKey and press Enter...")
        input()
        
        # Export certificate
        subprocess.run([
            "ykman", "piv", "certificates", "export", "9a", "/tmp/admin.pem"
        ], check=True)
        
        # Get certificate hash
        with open("/tmp/admin.pem", "rb") as f:
            cert_data = f.read()
        
        cert_hash = hashlib.sha256(cert_data).hexdigest()
        
        # Store admin
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO admin_auth (yubikey_cert_hash, role, created_at, created_by)
                VALUES (?, 'super_admin', ?, 'initial_setup')
            """, (cert_hash, int(time.time())))
        
        os.remove("/tmp/admin.pem")
        return cert_hash
    
    def _configure_initial_limits(self):
        """Configure initial spending limits"""
        limits = {
            "daily_total": 100.0,
            "per_transaction": 10.0,
            "blockchain_posting": 1.0,
            "auto_approve_threshold": 0.1
        }
        
        # Encrypt limits
        encrypted = self._encrypt_limits(limits)
        
        # Store
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO spending_limits (encrypted_data, nonce, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
            """, (encrypted['data'], encrypted['nonce'], 
                  int(time.time()), 'initial_setup'))
            
            # Set action permissions
            conn.executemany("""
                INSERT INTO action_permissions (action, require_yubikey, max_amount, daily_limit)
                VALUES (?, ?, ?, ?)
            """, [
                ('blockchain_post', True, 10.0, 50.0),
                ('ipfs_pin', False, 1.0, 100.0),
                ('domain_register', True, 5.0, 20.0)
            ])
    
    def _encrypt_limits(self, limits):
        """Encrypt spending limits using TPM-derived key"""
        # Get key from TPM
        key = self._derive_key_from_tpm()
        
        # Generate nonce
        nonce = os.urandom(12)
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        plaintext = json.dumps(limits).encode()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'data': ciphertext + encryptor.tag,
            'nonce': nonce
        }
    
    def _derive_key_from_tpm(self):
        """Derive AES key from TPM"""
        # Use TPM to generate deterministic key material
        subprocess.run([
            "tpm2_hmac", "-c", "0x81800000", "-o", "/tmp/keymaterial",
            "--hex", "brunnen-g-spending-limits"
        ], check=True)
        
        with open("/tmp/keymaterial", "rb") as f:
            key_material = f.read()
        
        os.remove("/tmp/keymaterial")
        
        # Derive AES key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'brunnen-g-salt',
            iterations=100000,
            backend=default_backend()
        )
        
        return kdf.derive(key_material)


class SpendingControl:
    def __init__(self, db_path):
        self.db_path = db_path
        self.admin_setup = AdminSetup(db_path)
    
    def authorize_transaction(self, action, amount, yubikey_cert=None):
        """Authorize a spending transaction"""
        # Check if action requires YubiKey
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT require_yubikey, max_amount, daily_limit 
                FROM action_permissions WHERE action = ?
            """, (action,))
            
            result = cursor.fetchone()
            if not result:
                return {"status": "error", "message": "Unknown action"}
            
            require_yubikey, max_amount, daily_limit = result
        
        # Verify YubiKey if required
        if require_yubikey:
            if not yubikey_cert:
                return {"status": "error", "message": "YubiKey required"}
            
            if not self._verify_admin_yubikey(yubikey_cert):
                return {"status": "error", "message": "Unauthorized YubiKey"}
        
        # Check amount limits
        if amount > max_amount:
            return {"status": "error", "message": f"Exceeds max amount: {max_amount}"}
        
        # Check daily limit
        daily_spent = self._get_daily_spent(action)
        if daily_spent + amount > daily_limit:
            return {"status": "error", "message": f"Exceeds daily limit: {daily_limit}"}
        
        # Check wallet balance
        wallet_balance = self._get_wallet_balance()
        if wallet_balance < amount:
            return {"status": "error", "message": "Insufficient wallet balance"}
        
        # Check stored limits
        stored_limits = self._decrypt_limits()
        if amount > stored_limits.get('per_transaction', 0):
            return {"status": "error", "message": "Exceeds stored transaction limit"}
        
        # All checks passed
        return {"status": "authorized", "amount": amount}
    
    def execute_transaction(self, action, amount, details, authorized_by=None):
        """Execute authorized transaction"""
        # Get balances
        balance_before = self._get_wallet_balance()
        
        # Perform transaction
        success = self._perform_blockchain_transaction(amount, details)
        
        if success:
            balance_after = balance_before - amount
            status = "completed"
        else:
            balance_after = balance_before
            status = "failed"
        
        # Log transaction
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO transaction_log 
                (timestamp, action, amount, balance_before, balance_after, 
                 authorized_by, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (int(time.time()), action, amount, balance_before, 
                  balance_after, authorized_by, status, json.dumps(details)))
        
        # Update stored balance
        if success:
            self._update_stored_balance(balance_after)
        
        return {"status": status, "balance": balance_after}
    
    def _verify_admin_yubikey(self, cert_data):
        """Verify admin YubiKey certificate"""
        cert_hash = hashlib.sha256(cert_data.encode()).hexdigest()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT role FROM admin_auth WHERE yubikey_cert_hash = ?
            """, (cert_hash,))
            
            result = cursor.fetchone()
            if result:
                # Update last auth time
                conn.execute("""
                    UPDATE admin_auth SET last_auth = ? WHERE yubikey_cert_hash = ?
                """, (int(time.time()), cert_hash))
                return True
            
            return False
    
    def _get_daily_spent(self, action):
        """Get amount spent today for action"""
        today_start = int(time.time()) - (int(time.time()) % 86400)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COALESCE(SUM(amount), 0) FROM transaction_log
                WHERE action = ? AND timestamp >= ? AND status = 'completed'
            """, (action, today_start))
            
            return cursor.fetchone()[0]
    
    def _get_wallet_balance(self):
        """Get current wallet balance from Emercoin"""
        try:
            result = subprocess.run([
                "emercoin-cli", "getbalance"
            ], capture_output=True, text=True, check=True)
            
            return float(result.stdout.strip())
        except:
            return 0.0
    
    def _decrypt_limits(self):
        """Decrypt stored spending limits"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT encrypted_data, nonce FROM spending_limits
                ORDER BY id DESC LIMIT 1
            """)
            
            result = cursor.fetchone()
            if not result:
                return {}
            
            encrypted_data, nonce = result
        
        # Get key from TPM
        key = self.admin_setup._derive_key_from_tpm()
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, encrypted_data[-16:]),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(encrypted_data[:-16]) + decryptor.finalize()
        
        return json.loads(plaintext.decode())
    
    def _perform_blockchain_transaction(self, amount, details):
        """Execute blockchain transaction"""
        try:
            # Example: Post to Emercoin NVS
            name = details.get('name', '')
            value = details.get('value', '')
            days = details.get('days', 365)
            
            result = subprocess.run([
                "emercoin-cli", "name_new", name, value, str(days)
            ], capture_output=True, text=True, check=True)
            
            return True
        except:
            return False
    
    def _update_stored_balance(self, new_balance):
        """Update encrypted stored balance"""
        limits = self._decrypt_limits()
        limits['last_balance'] = new_balance
        limits['last_update'] = int(time.time())
        
        encrypted = self.admin_setup._encrypt_limits(limits)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO spending_limits (encrypted_data, nonce, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
            """, (encrypted['data'], encrypted['nonce'], 
                  int(time.time()), 'system'))


# CLI Integration
def handle_blockchain_post(data, spending_control):
    """Handle blockchain posting with spending controls"""
    action = "blockchain_post"
    amount = data.get('cost', 1.0)
    
    # Get YubiKey cert if provided
    yubikey_cert = data.get('yubikey_cert')
    
    # Authorize
    auth_result = spending_control.authorize_transaction(
        action, amount, yubikey_cert
    )
    
    if auth_result['status'] != 'authorized':
        return auth_result
    
    # Execute
    tx_result = spending_control.execute_transaction(
        action, amount, 
        {
            'name': data.get('name'),
            'value': data.get('value'),
            'days': data.get('days', 365)
        },
        authorized_by=hashlib.sha256(yubikey_cert.encode()).hexdigest() if yubikey_cert else None
    )
    
    return tx_result