#!/usr/bin/env python3
"""
Brunnen-G API Daemon with AES Encryption and TPM Integrity
"""
import os
import json
import hashlib
import hmac
import subprocess
import sqlite3
import time
import logging
import re
import asyncio
import aiohttp
from datetime import datetime
from aiohttp import web
from threading import Lock
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import signal
import sys
import atexit


API_PORT = 8080
DB_DIR = os.environ.get('BRUNNEN_DB_DIR', './data')
DB_NAME = os.path.join(DB_DIR, 'brunnen.db')
MAX_PAYLOAD_SIZE = 1048576
ADDRESS_REGEX = re.compile(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.(coin|emc|lib|bazar)$')
DOMAIN_NAME = os.environ.get('BRUNNEN_DOMAIN', '')  # Set via environment
TPM_HANDLE = os.environ.get('BRUNNEN_TPM_HANDLE', '0x81000000')
INTEGRITY_CHECK_INTERVAL = 3600  # 1 hour

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    logging.info(f"Received signal {sig}, shutting down...")
    
    # Clean up resources
    if os.path.exists(HMAC_KEY_FILE):
        os.unlink(HMAC_KEY_FILE)
    
    # Remove PID file
    pid_file = "/tmp/brunnen_api.pid"
    if os.path.exists(pid_file):
        os.unlink(pid_file)
    
    logging.info("API daemon shutdown complete")
    sys.exit(0)

def cleanup():
    """Cleanup function for atexit"""
    pid_file = "/tmp/brunnen_api.pid"
    if os.path.exists(pid_file):
        os.unlink(pid_file)

# Register signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
atexit.register(cleanup)

os.makedirs(DB_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

class AESCrypto:
    def __init__(self):
        self.key = self._get_or_create_key()
    
    def _get_or_create_key(self):
        key_file = os.path.join(DB_DIR, '.aes_key')
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate key via TPM if available
            try:
                proc = subprocess.run(['tpm2_getrandom', '32'], 
                                    capture_output=True, timeout=5)
                if proc.returncode == 0:
                    key = proc.stdout
                else:
                    key = os.urandom(32)
            except:
                key = os.urandom(32)
            
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            return key
    
    def encrypt(self, plaintext):
        if not plaintext:
            return None
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return base64.b64encode(iv + ciphertext).decode()
    
    def decrypt(self, ciphertext):
        if not ciphertext:
            return None
        try:
            # Decode
            data = base64.b64decode(ciphertext)
            
            # Extract IV and ciphertext
            iv = data[:16]
            actual_ciphertext = data[16:]
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode()
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            return None

class MerkleTree:
    @staticmethod
    def hash_data(data):
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def calculate_merkle_root(leaves):
        if not leaves:
            return None
        
        # Hash all leaves
        current_level = [MerkleTree.hash_data(leaf) for leaf in leaves]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    combined = current_level[i] + current_level[i]
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            current_level = next_level
        
        return current_level[0]

class DatabaseIntegrity:
    def __init__(self, db_path, crypto):
        self.db_path = db_path
        self.crypto = crypto
        self.lock = Lock()
    
    async def calculate_db_merkle(self):
        leaves = []
        async with aiosqlite.connect(self.db_path) as db:
            # Get all PII data in deterministic order
            async with db.execute("""
                SELECT address, pubkey, ygg_pubkey, created_at 
                FROM address_keys ORDER BY address
            """) as cursor:
                async for row in cursor:
                    # Include encrypted values in merkle
                    leaf = f"{row[0]}|{row[1]}|{row[2]}|{row[3]}"
                    leaves.append(leaf)
        
        return MerkleTree.calculate_merkle_root(leaves)
    
    async def store_merkle_in_tpm(self, merkle_root):
        try:
            # Store in TPM NV memory
            proc = await asyncio.create_subprocess_exec(
                'tpm2_nvdefine', TPM_HANDLE, '-s', '32', '-a', 'ownerwrite|ownerread',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            # Write merkle root
            proc = await asyncio.create_subprocess_exec(
                'tpm2_nvwrite', TPM_HANDLE, '-i', '-',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate(input=merkle_root.encode())
            
            logging.info(f"Stored merkle root in TPM: {merkle_root[:16]}...")
            return True
        except Exception as e:
            logging.error(f"TPM merkle storage failed: {e}")
            # Fallback to file
            with open(os.path.join(DB_DIR, '.merkle'), 'w') as f:
                f.write(merkle_root)
            return False
    
    async def verify_merkle_from_tpm(self, current_merkle):
        try:
            # Read from TPM
            proc = await asyncio.create_subprocess_exec(
                'tpm2_nvread', TPM_HANDLE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            stored_merkle = stdout.decode().strip()
            
            return stored_merkle == current_merkle
        except:
            # Fallback to file
            try:
                with open(os.path.join(DB_DIR, '.merkle'), 'r') as f:
                    stored_merkle = f.read().strip()
                return stored_merkle == current_merkle
            except:
                return True  # First run
    
    async def verify_integrity(self):
        current_merkle = await self.calculate_db_merkle()
        if not await self.verify_merkle_from_tpm(current_merkle):
            logging.error("DATABASE INTEGRITY CHECK FAILED!")
            return False
        return True
    
    async def update_integrity(self):
        merkle_root = await self.calculate_db_merkle()
        await self.store_merkle_in_tpm(merkle_root)

class EconomicDefense:
    def __init__(self, db_path):
        self.db_path = db_path
        self.base_cost = 0.01
        self.base_period = 2  # Base period in days (2 days)
        self.lock = Lock()
        
    async def get_current_block_height(self):
        try:
            proc = await asyncio.create_subprocess_exec(
                'emercoin-cli', 'getblockcount',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                return int(stdout.decode().strip())
        except:
            pass
        return 0
    
    async def get_risk_record(self, domain, ygg_pubkey):
        risk_key = f"risk:{domain}:{ygg_pubkey}"
        try:
            proc = await asyncio.create_subprocess_exec(
                'emercoin-cli', 'name_show', risk_key,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                return json.loads(data.get('value', '{}'))
        except:
            pass
        return None
    
    async def get_all_risk_records_for_ygg(self, ygg_pubkey):
        all_records = []
        try:
            proc = await asyncio.create_subprocess_exec(
                'emercoin-cli', 'name_list', 'risk:',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                names = json.loads(stdout.decode())
                for name_data in names:
                    name = name_data.get('name', '')
                    if ygg_pubkey in name:
                        try:
                            value = json.loads(name_data.get('value', '{}'))
                            all_records.append(value)
                        except:
                            pass
        except:
            pass
        return all_records
    
    async def calculate_registration_cost(self, domain, ygg_pubkey):
        all_records = await self.get_all_risk_records_for_ygg(ygg_pubkey)
        domains_count = len(all_records)
        total_attempts = sum(record.get('attempts', 0) for record in all_records)
        exponent = total_attempts + domains_count
        return self.base_cost * (2 ** exponent)
    
    async def calculate_expiry_days(self, domain, ygg_pubkey):
        all_records = await self.get_all_risk_records_for_ygg(ygg_pubkey)
        domains_count = len(all_records)
        total_attempts = sum(record.get('attempts', 0) for record in all_records)
        exponent = total_attempts + domains_count
        return min(self.base_period * (2 ** exponent), 365 * 100)  # Cap at 100 years
    
    async def update_risk_record(self, domain, ygg_pubkey, username):
        risk_key = f"risk:{domain}:{ygg_pubkey}"
        current_height = await self.get_current_block_height()
        
        record = await self.get_risk_record(domain, ygg_pubkey)
        
        if record:
            record_data = {
                "attempts": record.get('attempts', 0) + 1,
                "user": username,
                "last_attempt_block": current_height
            }
        else:
            record_data = {
                "attempts": 1,
                "user": username,
                "last_attempt_block": current_height
            }
        
        expiry_days = await self.calculate_expiry_days(domain, ygg_pubkey)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                'emercoin-cli', 'name_update' if record else 'name_new',
                risk_key, json.dumps(record_data), str(expiry_days),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return proc.returncode == 0
        except:
            return False
    
    async def get_domain_owner_address(self, domain):
        # Check database first
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT owner_address FROM domain_settings WHERE domain = ?", 
                (domain,)
            ) as cursor:
                result = await cursor.fetchone()
                if result and result[0]:
                    return result[0]
        
        # Fall back to blockchain query
        try:
            proc = await asyncio.create_subprocess_exec(
                'emercoin-cli', 'name_show', f'dns:{domain}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                domain_data = json.loads(stdout.decode())
                owner_address = domain_data.get('address')
                
                # Cache in database
                if owner_address:
                    async with aiosqlite.connect(self.db_path) as db:
                        await db.execute("""
                            UPDATE domain_settings 
                            SET owner_address = ?, verified_at = ?
                            WHERE domain = ?
                        """, (owner_address, int(time.time()), domain))
                        await db.commit()
                
                return owner_address
        except:
            pass
        return None
    
    async def verify_domain_payment(self, domain, amount, tx_hash):
        owner_address = await self.get_domain_owner_address(domain)
        if not owner_address:
            return False
        
        try:
            proc = await asyncio.create_subprocess_exec(
                'emercoin-cli', 'gettransaction', tx_hash,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                tx_data = json.loads(stdout.decode())
                return (tx_data.get('amount', 0) >= amount and 
                       owner_address in str(tx_data.get('details', [])))
        except:
            pass
        return False

async def setup_database():
    async with aiosqlite.connect(DB_NAME) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS api_keys (
                app_name TEXT PRIMARY KEY,
                api_key_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                permissions TEXT DEFAULT 'read',
                created_at INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS address_keys (
                address TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                ygg_pubkey TEXT,
                created_at INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS domain_settings (
                domain TEXT PRIMARY KEY,
                owner_address TEXT,
                dnd_mode BOOLEAN DEFAULT 0,
                income_earned REAL DEFAULT 0,
                pending_updates INTEGER DEFAULT 0,
                last_blockchain_post INTEGER,
                verified_at INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS integrity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                merkle_root TEXT,
                verified BOOLEAN
            );
        """)
        await db.commit()

async def verify_domain_ownership():
    if not DOMAIN_NAME:
        logging.error("BRUNNEN_DOMAIN environment variable not set!")
        return False
    
    # Use semaphore to prevent concurrent verification
    async with domain_verification_lock:
        try:
            # Check if already verified recently
            async with aiosqlite.connect(DB_NAME) as db:
                async with db.execute(
                    "SELECT owner_address, verified_at FROM domain_settings WHERE domain = ?",
                    (DOMAIN_NAME,)
                ) as cursor:
                    result = await cursor.fetchone()
                    if result and result[1] and (time.time() - result[1] < 86400):  # 24 hours
                        logging.info(f"Domain already verified: {DOMAIN_NAME} (owner: {result[0]})")
                        return True
            
            # Verify from blockchain
            proc = await asyncio.create_subprocess_exec(
                'emercoin-cli', 'name_show', f'dns:{DOMAIN_NAME}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                domain_data = json.loads(stdout.decode())
                owner_address = domain_data.get('address')
                
                # Store verified domain info in database
                async with aiosqlite.connect(DB_NAME) as db:
                    await db.execute("""
                        INSERT OR REPLACE INTO domain_settings 
                        (domain, owner_address, verified_at)
                        VALUES (?, ?, ?)
                    """, (DOMAIN_NAME, owner_address, int(time.time())))
                    await db.commit()
                
                logging.info(f"Domain verified: {DOMAIN_NAME} (owner: {owner_address})")
                return True
        except Exception as e:
            logging.error(f"Domain verification error: {e}")
    
    logging.error(f"Domain verification failed: {DOMAIN_NAME}")
    return False

# Global semaphore for domain verification
domain_verification_lock = asyncio.Semaphore(1)

async def get_yggdrasil_pubkey():
    try:
        proc = await asyncio.create_subprocess_exec(
            'yggdrasilctl', 'getSelf',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            return data.get('key')
    except:
        pass
    return None

async def register_identity(request, economic_defense, crypto, integrity):
    try:
        data = await request.json()
    except:
        return web.json_response({"status": "error", "message": "Invalid JSON"}, status=400)
    
    username = data.get('username')
    domain = data.get('domain')
    tx_hash = data.get('tx_hash')
    ygg_pubkey = data.get('ygg_pubkey')
    
    if not username or not domain:
        return web.json_response({"status": "error", "message": "Missing username or domain"}, status=400)
    
    # Verify domain matches our domain
    if domain != DOMAIN_NAME:
        return web.json_response({"status": "error", "message": f"This node only handles {DOMAIN_NAME}"}, status=400)
    
    address = f"{username}@{domain}"
    if not ADDRESS_REGEX.match(address):
        return web.json_response({"status": "error", "message": "Invalid address format"}, status=400)
    
    if not ygg_pubkey:
        ygg_pubkey = await get_yggdrasil_pubkey()
        if not ygg_pubkey:
            return web.json_response({"status": "error", "message": "Yggdrasil public key required"}, status=400)
    
    required_cost = await economic_defense.calculate_registration_cost(domain, ygg_pubkey)
    
    if required_cost > economic_defense.base_cost:
        if not tx_hash:
            owner_address = await economic_defense.get_domain_owner_address(domain)
            if not owner_address:
                return web.json_response({"status": "error", "message": "Domain owner not found"}, status=500)
            
            return web.json_response({
                "status": "payment_required",
                "cost": required_cost,
                "currency": "EMC",
                "pay_to": owner_address,
                "domain": domain
            }, status=402)
        
        if not await economic_defense.verify_domain_payment(domain, required_cost, tx_hash):
            return web.json_response({"status": "payment_invalid", "required": required_cost}, status=400)
    
    try:
        proc = await asyncio.create_subprocess_exec(
            './tpm_provisioning.sh',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, 'USER': username, 'DOMAIN': domain}
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            raise Exception("TPM provisioning failed")
        
        pubkey = stdout.decode().strip()
        
        # Encrypt PII data
        encrypted_address = crypto.encrypt(address)
        encrypted_ygg = crypto.encrypt(ygg_pubkey)
        
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute("""
                INSERT OR REPLACE INTO address_keys (address, pubkey, ygg_pubkey, created_at) 
                VALUES (?, ?, ?, ?)
            """, (encrypted_address, pubkey, encrypted_ygg, int(time.time())))
            
            await db.execute("""
                UPDATE domain_settings 
                SET income_earned = income_earned + ?,
                    pending_updates = pending_updates + 1
                WHERE domain = ?
            """, (required_cost, domain))
            if not db.total_changes:
                await db.execute("""
                    INSERT INTO domain_settings (domain, income_earned, pending_updates)
                    VALUES (?, ?, 1)
                """, (domain, required_cost))
            await db.commit()
        
        # Update database integrity
        await integrity.update_integrity()
        
        await economic_defense.update_risk_record(domain, ygg_pubkey, username)
        
        return web.json_response({
            "status": "success",
            "address": address,
            "cost_paid": required_cost,
            "ygg_pubkey": ygg_pubkey
        })
        
    except Exception as e:
        return web.json_response({"status": "error", "message": str(e)}, status=500)

async def periodic_integrity_check(integrity):
    while True:
        await asyncio.sleep(INTEGRITY_CHECK_INTERVAL)
        try:
            if not await integrity.verify_integrity():
                logging.error("Periodic integrity check failed!")
                # Could trigger alerts or shutdown
        except Exception as e:
            logging.error(f"Integrity check error: {e}")

async def init_app():
    global aiosqlite
    import aiosqlite
    
    await setup_database()
    
    if not await verify_domain_ownership():
        raise Exception("Domain verification failed")
    
    app = web.Application()
    crypto = AESCrypto()
    integrity = DatabaseIntegrity(DB_NAME, crypto)
    economic_defense = EconomicDefense(DB_NAME)
    
    # Initial integrity check
    await integrity.update_integrity()
    
    # Start periodic integrity checks
    asyncio.create_task(periodic_integrity_check(integrity))
    
    # Routes
    app.router.add_get('/api/v1/health', lambda r: web.json_response({
        "status": "healthy", 
        "domain": DOMAIN_NAME,
        "timestamp": int(time.time())
    }))
    
    app.router.add_post('/api/v1/register', 
                       lambda r: register_identity(r, economic_defense, crypto, integrity))
    
    # CORS
    async def cors_middleware(request, handler):
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'X-API-Key, Content-Type'
        return response
    
    app.middlewares.append(cors_middleware)
    
    return app

def main():
    APIHandler.setup_database_once()
    
    print(f"Starting Brunnen-G API daemon on port {API_PORT}")
    print("API Version: 1.0.0")
    print(f"Database: {DB_NAME}")
    print(f"Logs: {LOG_FILE}")
    print(f"PID: {os.getpid()}")
    
    # Write PID file
    with open("/tmp/brunnen_api.pid", "w") as f:
        f.write(str(os.getpid()))
    
    try:
        server = HTTPServer(('', API_PORT), APIHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down API daemon")
        server.shutdown()
    finally:
        cleanup()

if __name__ == '__main__':
    main()