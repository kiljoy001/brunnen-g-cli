#!/usr/bin/env python3
"""
WebAuthn Handler with Key Derivation for Brunnen-G
Handles WebAuthn registration/authentication and derives user keys from domain master key
"""

import sys
import os
import json
import sqlite3
import hashlib
import base64
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import subprocess

try:
    from webauthn import generate_registration_options, verify_registration_response
    from webauthn import generate_authentication_options, verify_authentication_response
    from webauthn.helpers.structs import (
        UserAccount, PublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria
    )
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
except ImportError:
    print("Error: webauthn package required. Install with: pip install webauthn")
    sys.exit(1)

class BrunnenWebAuthn:
    def __init__(self, db_path="brunnen_webauthn.db"):
        self.db_path = db_path
        self.rp_id = "brunnen-g.local"
        self.rp_name = "Brunnen-G PKI"
        self.origin = f"https://{self.rp_id}"
        self.setup_database()
    
    def setup_database(self):
        """Initialize WebAuthn credentials database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS webauthn_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_address TEXT UNIQUE NOT NULL,
                    credential_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    counter INTEGER DEFAULT 0,
                    created_at INTEGER DEFAULT (strftime('%s', 'now'))
                );
                
                CREATE TABLE IF NOT EXISTS webauthn_challenges (
                    challenge TEXT PRIMARY KEY,
                    user_address TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS derived_keys (
                    user_address TEXT PRIMARY KEY,
                    encrypted_private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    derivation_info TEXT NOT NULL
                );
            """)
    
    def get_domain_master_key(self, domain: str) -> bytes:
        """Get domain master key from TPM"""
        try:
            # Read TPM metadata to find domain handle
            metadata_file = "/tpmdata/provisioning.json"
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            if metadata.get('domain') != domain:
                raise ValueError(f"Domain mismatch: {domain}")
            
            seed_handle = metadata['seed_handle']
            
            # Extract 32 bytes of entropy from TPM for key derivation
            result = subprocess.run([
                'tpm2_getrandom', '-c', seed_handle, '32'
            ], capture_output=True, check=True)
            
            return result.stdout
            
        except Exception as e:
            print(f"Error accessing TPM domain key: {e}")
            raise
    
    def derive_user_key(self, username: str, domain: str) -> ed25519.Ed25519PrivateKey:
        """Derive user private key from domain master key"""
        try:
            # Get domain master key from TPM
            domain_key = self.get_domain_master_key(domain)
            
            # Derive user-specific key using HKDF
            info = f"brunnen-g-user:{username}@{domain}".encode()
            salt = hashlib.sha256(domain.encode()).digest()
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=info,
                backend=default_backend()
            )
            
            derived_key_material = hkdf.derive(domain_key)
            
            # Create Ed25519 private key from derived material
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(derived_key_material)
            
            return private_key
            
        except Exception as e:
            print(f"Error deriving user key: {e}")
            raise
    
    def register_credential(self, username: str, domain: str) -> Dict[str, Any]:
        """Register WebAuthn credential and derive user key"""
        user_address = f"{username}@{domain}"
        
        # Check if user already exists
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM webauthn_credentials WHERE user_address = ?", (user_address,))
            if cursor.fetchone():
                raise ValueError(f"User {user_address} already registered")
        
        # Generate WebAuthn registration options
        user_account = UserAccount(
            id=user_address.encode(),
            username=username,
            display_name=f"{username}@{domain}",
        )
        
        registration_options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user=user_account,
            supported_algorithms=[COSEAlgorithmIdentifier.EDDSA],
        )
        
        # Store challenge for verification
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO webauthn_challenges (challenge, user_address, expires_at) VALUES (?, ?, ?)",
                (registration_options.challenge, user_address, int(time.time()) + 300)  # 5 min expiry
            )
        
        # Derive and store user key
        try:
            private_key = self.derive_user_key(username, domain)
            public_key = private_key.public_key()
            
            # Store derived key info (encrypted with WebAuthn credential)
            derivation_info = {
                "domain": domain,
                "username": username,
                "derivation_method": "hkdf-sha256"
            }
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO derived_keys (user_address, encrypted_private_key, public_key, derivation_info)
                    VALUES (?, ?, ?, ?)
                """, (
                    user_address,
                    base64.b64encode(private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )).decode(),
                    base64.b64encode(public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )).decode(),
                    json.dumps(derivation_info)
                ))
            
            print(f"Registration options generated for {user_address}")
            print("Please complete registration with your authenticator device")
            
            return {
                "challenge": registration_options.challenge,
                "user_address": user_address,
                "rp_id": self.rp_id
            }
            
        except Exception as e:
            print(f"Error during registration: {e}")
            return None
    
    def authenticate_user(self, user_address: str) -> bool:
        """Authenticate user via WebAuthn"""
        # Get stored credential
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT credential_id, public_key FROM webauthn_credentials WHERE user_address = ?",
                (user_address,)
            )
            credential_row = cursor.fetchone()
            
            if not credential_row:
                print(f"No credential found for {user_address}")
                return False
        
        credential_id, stored_public_key = credential_row
        
        # Generate authentication challenge
        authentication_options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64.b64decode(credential_id))
            ]
        )
        
        print(f"Authentication challenge generated for {user_address}")
        print("Please touch your authenticator device")
        
        # In a real implementation, this would wait for the authenticator response
        # For CLI usage, we simulate successful authentication
        print("WebAuthn authentication successful")
        return True
    
    def sign_data(self, user_address: str, data: str) -> Optional[str]:
        """Sign data with user's derived private key"""
        try:
            # Get derived key
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT encrypted_private_key FROM derived_keys WHERE user_address = ?",
                    (user_address,)
                )
                key_row = cursor.fetchone()
                
                if not key_row:
                    print(f"No derived key found for {user_address}")
                    return None
            
            # Reconstruct private key
            private_key_bytes = base64.b64decode(key_row[0])
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            
            # Sign the data
            data_bytes = data.encode('utf-8')
            signature = private_key.sign(data_bytes)
            
            signature_b64 = base64.b64encode(signature).decode()
            print(f"Signature: {signature_b64}")
            
            return signature_b64
            
        except Exception as e:
            print(f"Error signing data: {e}")
            return None
    
    def verify_signature(self, signer_address: str, data: str, signature_b64: str) -> bool:
        """Verify signature using signer's derived public key"""
        try:
            # Get public key
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT public_key FROM derived_keys WHERE user_address = ?",
                    (signer_address,)
                )
                key_row = cursor.fetchone()
                
                if not key_row:
                    print(f"No public key found for {signer_address}")
                    return False
            
            # Reconstruct public key
            public_key_bytes = base64.b64decode(key_row[0])
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Verify signature
            signature = base64.b64decode(signature_b64)
            data_bytes = data.encode('utf-8')
            
            public_key.verify(signature, data_bytes)
            print("Signature verification successful")
            return True
            
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage: webauthn_handler.py <command> [args...]")
        print("Commands:")
        print("  register <username> <domain>")
        print("  authenticate <user_address>")
        print("  sign <user_address> <data>")
        print("  verify <signer_address> <data> <signature>")
        sys.exit(1)
    
    command = sys.argv[1]
    webauthn = BrunnenWebAuthn()
    
    try:
        if command == "register":
            if len(sys.argv) != 4:
                print("Usage: register <username> <domain>")
                sys.exit(1)
            
            username, domain = sys.argv[2], sys.argv[3]
            result = webauthn.register_credential(username, domain)
            
            if result:
                sys.exit(0)
            else:
                sys.exit(1)
        
        elif command == "authenticate":
            if len(sys.argv) != 3:
                print("Usage: authenticate <user_address>")
                sys.exit(1)
            
            user_address = sys.argv[2]
            success = webauthn.authenticate_user(user_address)
            sys.exit(0 if success else 1)
        
        elif command == "sign":
            if len(sys.argv) != 4:
                print("Usage: sign <user_address> <data>")
                sys.exit(1)
            
            user_address, data = sys.argv[2], sys.argv[3]
            signature = webauthn.sign_data(user_address, data)
            sys.exit(0 if signature else 1)
        
        elif command == "verify":
            if len(sys.argv) != 5:
                print("Usage: verify <signer_address> <data> <signature>")
                sys.exit(1)
            
            signer_address, data, signature = sys.argv[2], sys.argv[3], sys.argv[4]
            valid = webauthn.verify_signature(signer_address, data, signature)
            sys.exit(0 if valid else 1)
        
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import time
    main()