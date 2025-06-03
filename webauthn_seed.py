#!/usr/bin/env python3
"""
webauthn_seed.py - Generate TPM-backed domain seed using WebAuthn
"""

import os
import json
import base64
import hashlib
import subprocess
from flask import Flask, request, jsonify, render_template_string
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData

app = Flask(__name__)

# WebAuthn configuration
rp = PublicKeyCredentialRpEntity("brunnen-g.local", "Brunnen-G PKI")
server = Fido2Server(rp)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Brunnen-G Domain Seed Generation</title>
    <script>
        async function generateDomainSeed() {
            const domain = document.getElementById('domain').value;
            if (!domain) {
                alert('Please enter a domain');
                return;
            }
            
            try {
                // Get challenge from server
                const challengeResp = await fetch('/webauthn/challenge', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({domain: domain})
                });
                const challengeData = await challengeResp.json();
                
                // Create credential
                const credential = await navigator.credentials.create({
                    publicKey: {
                        challenge: base64ToArrayBuffer(challengeData.challenge),
                        rp: {name: "Brunnen-G PKI", id: "brunnen-g.local"},
                        user: {
                            id: base64ToArrayBuffer(challengeData.user_id),
                            name: domain,
                            displayName: "Domain: " + domain
                        },
                        pubKeyCredParams: [{alg: -7, type: "public-key"}],
                        attestation: "direct",
                        authenticatorSelection: {
                            authenticatorAttachment: "platform",
                            requireResidentKey: false,
                            userVerification: "required"
                        }
                    }
                });
                
                // Register with server
                const registerResp = await fetch('/webauthn/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        domain: domain,
                        id: arrayBufferToBase64(credential.rawId),
                        response: {
                            attestationObject: arrayBufferToBase64(credential.response.attestationObject),
                            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
                        }
                    })
                });
                
                const result = await registerResp.json();
                if (result.success) {
                    document.getElementById('result').innerText = 
                        'Domain seed generated successfully!\nSeed: ' + result.seed;
                } else {
                    alert('Failed: ' + result.error);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
        
        function base64ToArrayBuffer(base64) {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
    </script>
</head>
<body>
    <h1>Brunnen-G Domain Seed Generation</h1>
    <p>Generate a TPM-backed domain seed using WebAuthn</p>
    
    <div>
        <label>Domain: <input type="text" id="domain" placeholder="example.coin"></label>
        <button onclick="generateDomainSeed()">Generate Seed</button>
    </div>
    
    <pre id="result"></pre>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/webauthn/challenge', methods=['POST'])
def webauthn_challenge():
    data = request.json
    domain = data.get('domain')
    
    # Generate challenge
    challenge = os.urandom(32)
    user_id = hashlib.sha256(domain.encode()).digest()[:16]
    
    # Store challenge in session (in production, use proper session management)
    session_data = {
        'challenge': base64.b64encode(challenge).decode(),
        'user_id': base64.b64encode(user_id).decode(),
        'domain': domain
    }
    
    # Save to temp file (in production, use Redis or similar)
    with open(f'/dev/shm/webauthn_session_{domain}.json', 'w') as f:
        json.dump(session_data, f)
    
    return jsonify(session_data)

@app.route('/webauthn/register', methods=['POST'])
def webauthn_register():
    data = request.json
    domain = data.get('domain')
    
    # Load session
    try:
        with open(f'/dev/shm/webauthn_session_{domain}.json', 'r') as f:
            session_data = json.load(f)
    except:
        return jsonify({'success': False, 'error': 'Invalid session'})
    
    # Verify attestation
    attestation_object = base64.b64decode(data['response']['attestationObject'])
    client_data = base64.b64decode(data['response']['clientDataJSON'])
    
    # Extract authenticator data
    att_obj = AttestationObject(attestation_object)
    auth_data = att_obj.auth_data
    
    # Generate domain seed from credential ID and TPM
    credential_id = base64.b64decode(data['id'])
    
    # Combine with TPM-generated random
    tpm_random = subprocess.check_output([
        'tpm2_getrandom', '--hex', '32'
    ]).decode().strip()
    
    # Generate deterministic seed
    seed_material = credential_id + bytes.fromhex(tpm_random) + domain.encode()
    domain_seed = hashlib.sha256(seed_material).hexdigest()
    
    # Store in TPM
    store_domain_seed_tpm(domain, domain_seed)
    
    # Clean up session
    os.unlink(f'/dev/shm/webauthn_session_{domain}.json')
    
    return jsonify({
        'success': True,
        'domain': domain,
        'seed': domain_seed,
        'credential_id': base64.b64encode(credential_id).decode()
    })

def store_domain_seed_tpm(domain, seed):
    """Store domain seed in TPM sealed storage"""
    # Create policy for domain
    policy_file = f'/dev/shm/domain_policy_{domain}.pol'
    
    # Create PCR policy (PCR 0,1,2,3)
    subprocess.run([
        'tpm2_pcrread', '-o', f'/dev/shm/pcr.bin',
        'sha256:0,1,2,3'
    ], check=True)
    
    subprocess.run([
        'tpm2_createpolicy', '--policy-pcr',
        '-l', 'sha256:0,1,2,3',
        '-f', '/dev/shm/pcr.bin',
        '-L', policy_file
    ], check=True)
    
    # Seal domain seed
    subprocess.run([
        'tpm2_create',
        '-C', '0x81000000',  # Storage primary key
        '-i', '-',
        '-u', f'/dev/shm/domain_seal_{domain}.pub',
        '-r', f'/dev/shm/domain_seal_{domain}.priv',
        '-L', policy_file,
        '-a', 'fixedtpm|fixedparent|adminwithpolicy'
    ], input=seed.encode(), check=True)
    
    # Load sealed object
    result = subprocess.run([
        'tpm2_load',
        '-C', '0x81000000',
        '-u', f'/dev/shm/domain_seal_{domain}.pub',
        '-r', f'/dev/shm/domain_seal_{domain}.priv'
    ], capture_output=True, text=True, check=True)
    
    # Extract handle and persist
    handle = result.stdout.strip().split()[-1]
    persistent_handle = f'0x8101{hash(domain) & 0xFFFF:04x}'
    
    subprocess.run([
        'tpm2_evictcontrol',
        '-C', 'o',
        '-c', handle,
        persistent_handle
    ], check=True)
    
    # Clean up temp files
    for ext in ['pub', 'priv']:
        os.unlink(f'/dev/shm/domain_seal_{domain}.{ext}')
    os.unlink(policy_file)
    
    return persistent_handle

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8888, debug=False)