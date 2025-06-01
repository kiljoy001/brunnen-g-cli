#!/usr/bin/env python3
"""
TPM Metadata Protection - Complete Implementation
"""
import os
import json
import hashlib
import subprocess
import tempfile
import logging
import time
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class TPMMetadataError(Exception):
    """TPM metadata operation errors"""
    pass

class TPMMetadataProtection:
    """Secure TPM metadata encryption/decryption using YubiKey"""
    
    def __init__(self, tpm_dir="./tpmdata"):
        self.tpm_dir = Path(tpm_dir)
        self.challenge_file = self.tpm_dir / ".challenge"
        self.encrypted_file = self.tpm_dir / "provisioning.enc"
        self.temp_json_file = self.tpm_dir / "provisioning.json"
        
        # Ensure directory exists with secure permissions
        self.tpm_dir.mkdir(mode=0o700, exist_ok=True)
    
    def generate_challenge(self) -> str:
        """Generate and store a new YubiKey challenge"""
        try:
            # Generate 32-byte random challenge
            challenge = os.urandom(32).hex()
            
            # Write challenge with secure permissions
            with open(self.challenge_file, 'w') as f:
                f.write(challenge)
            os.chmod(self.challenge_file, 0o600)
            
            logger.info("Generated new YubiKey challenge")
            return challenge
            
        except Exception as e:
            raise TPMMetadataError(f"Failed to generate challenge: {e}")
    
    def get_yubikey_response(self, challenge: str) -> str:
        """Get YubiKey challenge-response"""
        try:
            # Validate YubiKey is present
            check_result = subprocess.run(['ykman', 'list'], 
                                        capture_output=True, text=True, timeout=5)
            if check_result.returncode != 0:
                raise TPMMetadataError("No YubiKey detected")
            
            # Get challenge-response (slot 2, hex mode)
            result = subprocess.run(['ykchalresp', '-2', '-x', challenge],
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                raise TPMMetadataError(f"YubiKey challenge failed: {result.stderr}")
            
            response = result.stdout.strip()
            if len(response) != 40:  # 32 bytes = 64 hex chars
                raise TPMMetadataError("Invalid YubiKey response length")
                
            return response
            
        except subprocess.TimeoutExpired:
            raise TPMMetadataError("YubiKey operation timeout")
        except Exception as e:
            raise TPMMetadataError(f"YubiKey error: {e}")
    
    def encrypt_metadata(self, metadata: Dict) -> bool:
        """Encrypt TPM metadata using YubiKey-derived key"""
        try:
            # Generate new challenge if needed
            if not self.challenge_file.exists():
                challenge = self.generate_challenge()
            else:
                with open(self.challenge_file, 'r') as f:
                    challenge = f.read().strip()
            
            # Get YubiKey response
            aes_key = self.get_yubikey_response(challenge)
            
            # Validate metadata
            if not isinstance(metadata, dict):
                raise TPMMetadataError("Metadata must be dictionary")
            
            # Add integrity hash
            metadata_json = json.dumps(metadata, sort_keys=True)
            metadata['integrity_hash'] = hashlib.sha256(metadata_json.encode()).hexdigest()
            
            # Create temporary file for plaintext
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                json.dump(metadata, temp_file, indent=2)
                temp_path = temp_file.name
            
            try:
                # Encrypt using OpenSSL with secure method
                encrypt_cmd = [
                    'openssl', 'enc', '-aes-256-cbc', '-pbkdf2',
                    '-in', temp_path,
                    '-out', str(self.encrypted_file),
                    '-pass', f'pass:{aes_key}'
                ]
                
                result = subprocess.run(encrypt_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    raise TPMMetadataError(f"Encryption failed: {result.stderr}")
                
                # Set secure permissions
                os.chmod(self.encrypted_file, 0o600)
                
                logger.info("TPM metadata encrypted successfully")
                return True
                
            finally:
                # Always cleanup temp file
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise TPMMetadataError(f"Failed to encrypt metadata: {e}")
    
    def decrypt_metadata(self) -> Dict:
        """Decrypt TPM metadata using YubiKey"""
        try:
            # Check encrypted file exists
            if not self.encrypted_file.exists():
                raise TPMMetadataError("No encrypted metadata found")
            
            # Check challenge file exists
            if not self.challenge_file.exists():
                raise TPMMetadataError("Challenge file missing")
            
            # Read challenge
            with open(self.challenge_file, 'r') as f:
                challenge = f.read().strip()
            
            # Get YubiKey response
            aes_key = self.get_yubikey_response(challenge)
            
            # Decrypt to temporary file
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_path = temp_file.name
            
            try:
                decrypt_cmd = [
                    'openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-d',
                    '-in', str(self.encrypted_file),
                    '-out', temp_path,
                    '-pass', f'pass:{aes_key}'
                ]
                
                result = subprocess.run(decrypt_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    raise TPMMetadataError(f"Decryption failed: {result.stderr}")
                
                # Read and validate JSON
                with open(temp_path, 'r') as f:
                    metadata = json.load(f)
                
                # Verify integrity if hash present
                if 'integrity_hash' in metadata:
                    stored_hash = metadata.pop('integrity_hash')
                    current_json = json.dumps(metadata, sort_keys=True)
                    current_hash = hashlib.sha256(current_json.encode()).hexdigest()
                    
                    if stored_hash != current_hash:
                        raise TPMMetadataError("Metadata integrity check failed")
                
                logger.info("TPM metadata decrypted successfully")
                return metadata
                
            finally:
                # Always cleanup temp file
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise TPMMetadataError(f"Failed to decrypt metadata: {e}")
    
    def get_tpm_handles(self) -> Dict[str, str]:
        """Get TPM handles from encrypted metadata"""
        try:
            metadata = self.decrypt_metadata()
            
            required_keys = ['primary_handle', 'key_handle']
            handles = {}
            
            for key in required_keys:
                if key not in metadata:
                    raise TPMMetadataError(f"Missing required handle: {key}")
                handles[key] = metadata[key]
            
            return handles
            
        except Exception as e:
            raise TPMMetadataError(f"Failed to get handles: {e}")
    
    def store_tpm_handles(self, primary_handle: str, key_handle: str, 
                         additional_data: Optional[Dict] = None) -> bool:
        """Store TPM handles in encrypted format"""
        try:
            # Validate handle format
            handle_pattern = r'^0x[0-9a-fA-F]{8}$'
            import re
            
            if not re.match(handle_pattern, primary_handle):
                raise TPMMetadataError(f"Invalid primary handle format: {primary_handle}")
            
            if not re.match(handle_pattern, key_handle):
                raise TPMMetadataError(f"Invalid key handle format: {key_handle}")
            
            # Create metadata structure
            metadata = {
                'primary_handle': primary_handle,
                'key_handle': key_handle,
                'created_at': int(time.time()),
                'version': '1.0'
            }
            
            # Add additional data if provided
            if additional_data:
                metadata.update(additional_data)
            
            # Encrypt and store
            return self.encrypt_metadata(metadata)
            
        except Exception as e:
            raise TPMMetadataError(f"Failed to store handles: {e}")
    
    def cleanup_temp_files(self):
        """Clean up any temporary decrypted files"""
        try:
            if self.temp_json_file.exists():
                os.unlink(self.temp_json_file)
                logger.debug("Cleaned up temporary files")
        except Exception as e:
            logger.warning(f"Cleanup warning: {e}")

# Integration functions for existing code
def secure_decrypt_tpm_metadata() -> Dict[str, str]:
    """Secure replacement for decrypt_tpm_metadata()"""
    try:
        protector = TPMMetadataProtection()
        handles = protector.get_tpm_handles()
        
        # Always cleanup after use
        protector.cleanup_temp_files()
        
        return handles
        
    except TPMMetadataError as e:
        logger.error(f"TPM metadata error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise TPMMetadataError(f"Metadata operation failed: {e}")

def store_tpm_metadata(primary_handle: str, key_handle: str) -> bool:
    """Store TPM handles securely"""
    try:
        protector = TPMMetadataProtection()
        return protector.store_tpm_handles(primary_handle, key_handle)
        
    except TPMMetadataError as e:
        logger.error(f"Failed to store metadata: {e}")
        return False