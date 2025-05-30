#!/usr/bin/env python3
"""
Generate signed manifest for TPM script validation
Run this after updating scripts to generate new signatures
"""
import json
import hashlib
import subprocess
import sys
from pathlib import Path

# Script directory and files
SCRIPT_DIR = "./tpm"
SCRIPTS = [
    "tpm_provisioning.sh",
    "tpm_random_number.sh", 
    "tpm_self_signed_cert.sh",
    "tpm_sign_data.sh",
    "tpm_verify_signature.sh"
]

def calculate_script_hashes():
    """Calculate SHA256 hashes for all scripts"""
    script_hashes = {}
    
    for script_name in SCRIPTS:
        script_path = Path(SCRIPT_DIR) / script_name
        
        if not script_path.exists():
            print(f"Warning: Script not found: {script_name}")
            continue
            
        with open(script_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            script_hashes[script_name] = file_hash
            print(f"✓ {script_name}: {file_hash[:16]}...")
    
    return script_hashes

def get_tpm_handle():
    """Get TPM handle for signing"""
    try:
        with open("/tpmdata/provisioning.json", 'r') as f:
            metadata = json.load(f)
            return metadata.get('seed_handle')
    except:
        handle = input("Enter TPM handle (0x81xxxxxx): ")
        if not handle.startswith('0x'):
            handle = f"0x{handle}"
        return handle

def sign_manifest(script_hashes, tpm_handle):
    """Sign manifest with TPM"""
    # Create canonical JSON representation
    manifest_data = json.dumps(script_hashes, sort_keys=True, separators=(',', ':'))
    
    # Write to temp file
    with open('/tmp/manifest.json', 'w') as f:
        f.write(manifest_data)
    
    print(f"Signing manifest with TPM handle: {tmp_handle}")
    
    # Sign with TPM
    try:
        result = subprocess.run([
            f"{SCRIPT_DIR}/tmp_sign_data.sh",
            "/tmp/manifest.json",
            tmp_handle
        ], capture_output=True, text=True, check=True)
        
        signature = result.stdout.strip()
        print(f"✓ Signature generated: {signature[:32]}...")
        return signature
        
    except subprocess.CalledProcessError as e:
        print(f"Error signing manifest: {e}")
        return None

def get_tpm_public_key(tmp_handle):
    """Extract TPM public key"""
    try:
        result = subprocess.run([
            'tpm2_readpublic', '-c', tpm_handle, '-f', 'der'
        ], capture_output=True, check=True)
        
        # Convert DER to hex
        pubkey_hex = result.stdout.hex()
        print(f"✓ Public key extracted: {pubkey_hex[:32]}...")
        return pubkey_hex
        
    except subprocess.CalledProcessError as e:
        print(f"Error extracting public key: {e}")
        return None

def generate_code_snippet(script_hashes, signature, pubkey):
    """Generate Python code for copy/paste"""
    code = f'''# TPM Script Validation - Generated {__import__('datetime').datetime.now()}
TPM_SCRIPT_HASHES = {json.dumps(script_hashes, indent=4)}

# TPM signature of above manifest
MANIFEST_SIGNATURE = "{signature}"

# TPM public key (DER format, hex encoded)
TPM_PUBLIC_KEY = "{pubkey}"

def verify_manifest_signature():
    """Verify TPM signature on script hashes"""
    import json
    import subprocess
    import tempfile
    
    manifest_data = json.dumps(TPM_SCRIPT_HASHES, sort_keys=True, separators=(',', ':'))
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        f.write(manifest_data)
        manifest_file = f.name
    
    try:
        # Get TPM handle from metadata
        with open("/tpmdata/provisioning.json", 'r') as f:
            metadata = json.load(f)
            handle = metadata.get('seed_handle')
        
        # Verify signature
        result = subprocess.run([
            './tpm/tmp_verify_signature.sh',
            manifest_file,
            MANIFEST_SIGNATURE,
            handle
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise SecurityError("TPM script manifest signature verification failed")
            
    finally:
        import os
        os.unlink(manifest_file)
'''
    return code

def main():
    print("=== TPM Script Manifest Generator ===")
    
    # Calculate hashes
    print("\n1. Calculating script hashes...")
    script_hashes = calculate_script_hashes()
    
    if not script_hashes:
        print("No scripts found to hash")
        return
    
    # Get TPM handle
    print("\n2. Getting TPM handle...")
    tmp_handle = get_tpm_handle()
    
    # Sign manifest
    print("\n3. Signing manifest...")
    signature = sign_manifest(script_hashes, tpm_handle)
    
    if not signature:
        print("Failed to sign manifest")
        return
    
    # Get public key
    print("\n4. Extracting public key...")
    pubkey = get_tpm_public_key(tpm_handle)
    
    if not pubkey:
        print("Failed to extract public key")
        return
    
    # Generate code
    print("\n5. Generating code snippet...")
    code_snippet = generate_code_snippet(script_hashes, signature, pubkey)
    
    # Save to file
    with open('tpm_manifest_code.py', 'w') as f:
        f.write(code_snippet)
    
    print("\n" + "="*60)
    print("Generated code saved to: tpm_manifest_code.py")
    print("Copy and paste the contents into your API daemon")
    print("="*60)
    
    # Also print to console
    print("\n" + code_snippet)

if __name__ == "__main__":
    main()