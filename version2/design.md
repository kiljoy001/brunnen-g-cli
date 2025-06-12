# Brunnen-G Identity System Documentation

## Overview

Brunnen-G implements a decentralized public key infrastructure using hardware security modules, blockchain persistence, and quantum-resistant cryptography. The system enables passwordless authentication without central authorities.

## Core Identity Equation

Each identity is computed as:
```
Let:
 H(.) denote the SHA256 hash function
 || donote the concatenation operator
 TPMpk represents the tpm public key
 DILsig represents the dilithium signature of the emercoin signed hash of the TPMpk
 YUBIpk represents the exportable yubikey public key using for signing nonce data

 First define the Domain Identity Hash(DIh):
 DIh = H(TPMpk || H(DILsig))

 Then, the Stable Identity Hash (IDstable):
 IDstable = H(DIh || H(YUBIpk))

 IDstable becomes the leaf in the merkle tree providing a reliable and unchanging idenitifier for each user or device.

```

### Components

**TPM Public Key**
- Hardware-generated key that never leaves the TPM
- Provides root of trust anchored in silicon
- Enables secure nonce generation for zero-knowledge proofs

**Emercoin Domain Signature**
- Proves domain ownership through blockchain
- Signs the TPM public key with domain's private key
- Creates binding between hardware and blockchain identity

**Dilithium Signature**
- Post-quantum cryptographic signature
- Signs the Emercoin signature for quantum resistance
- NIST-approved algorithm (FIPS 204)

**TPM Nonce**
- Fresh randomness for each authentication
- Prevents replay attacks
- Enables zero-knowledge property

**YubiKey Component**
- PIV certificate stored in slot 9a with merkle proof in a x509 extension 
- Requires physical touch for operations
- Acts as uncopyable bearer token
- Key is a FIDO2 resident credential generated for signing challenges for authentication (touch only)

## Registration Process

### Step 1: Identity Generation
1. TPM generates keypair (stays in hardware)
2. Domain owner signs TPM public key
3. Dilithium signs the domain signature
4. YubiKey generates certificate

### Step 2: Database Aggregation
1. Domain collects all identity records
2. Computes merkle root of identity set
3. Publishes database to IPFS
4. Stores only reference on blockchain:
   ```
   trust:domain.coin = {
     "cid": "QmHash...",
     "merkle_root": "0xabc123..."
   }
   ```

**Limitation**: Individual identities are not stored on-chain to reduce costs. Users must trust IPFS availability or maintain local copies.

## Verification Process

### Fast Path (Bloom Filter)
- O(1) lookup to check if identity might exist
- Prevents expensive operations on invalid identities
- Sub-microsecond response time

### Standard Path (Database)
1. Fetch domain's database from IPFS
2. Verify merkle root matches blockchain
3. Query local database for identity
4. Extract public keys and signatures

### Merkle Proof Path (Lightweight)
1. User provides merkle proof with identity data
2. Verify proof against blockchain merkle root
3. No database download required
4. Instant verification with minimal data
5. Proof stored on yubikey in certificate in slot 9a with custom OID of 63716

### Authentication Flow
1. Verifier generates random nonce via TPM
2. Sends nonce challenge to user
3. User signs (previous_hashes + nonce) with YubiKey
4. Verifier checks signature against stored public key
5. Physical touch required on YubiKey

## Zero-Knowledge Properties

**What the verifier learns:**
- Identity exists and is valid
- User currently possesses the hardware

**What remains secret:**
- All private keys
- Internal computation methods
- Hardware-specific details

## Database Structure

### Enhanced Schema with Merkle Proofs

**address_keys table**
```
- username: name of the user, must be unique in the domain
- tpm_pubkey: TPM public key
- dilithium_sig: Domain signature
- merkle_proof: JSON array of proof nodes
- merkle_index: Leaf position in tree
```

**db_root table**
```
- merkle_root: Current root hash
- identity_count: Total identities
- tree_height: Merkle tree depth
- timestamp: Last update time
```

### User Experience Benefits

With merkle proofs stored per user:
- Offline verification using only proof + root
- Mobile-friendly (no large DB downloads)
- Instant identity verification
- Privacy-preserving (don't reveal all users)

Users can export their proof as QR code or file for truly portable identity verification.

### Per-Identity Storage
- Not stored individually on blockchain
- Aggregated into domain databases
- Merkle proofs enable membership verification

### Domain-Level Operations
- Batch identity updates daily/weekly
- Single blockchain transaction per batch
- IPFS distributes full database
- Nodes cache frequently accessed domains

### Cost Model
- ~$0.01 per domain update (not per user)
- Users prove membership via merkle proof
- Database downloads amortized across queries

## Security Properties

**Hardware Binding**
- Private keys physically locked in TPM/YubiKey
- Cannot be extracted even with root access
- Survives OS compromise

**Quantum Resistance**
- Dilithium signatures resist quantum attacks
- Hash functions provide 256-bit quantum security
- Forward-secure design

**Physical Presence**
- YubiKey touch prevents remote attacks
- Rate-limited by human interaction
- Visible security indicator

**No Single Point of Failure**
- Any node can verify identities
- No central certificate authority
- Blockchain provides persistence

## Domain Certificate Authority

Domains can operate as their own CA:
1. Generate domain TPM keypair
2. Create self-signed CA certificate
3. Sign certificate hash with TPM
4. Publish to blockchain as `ca:domain.coin`

This enables:
- Domain-issued TLS certificates
- Service authentication
- Code signing
- Email encryption

## Network Integration

**API Access**
- REST endpoints for verification
- HMAC-authenticated requests
- Standard HTTP status codes (200/403)

**VoIP Support**
- Identity-based dialing (user@domain.coin)
- Asterisk AGI integration
- SIP over Yggdrasil mesh

**PAM Module**
- System login via Brunnen-G identity
- Replaces passwords for SSH/sudo
- Offline verification capability

## Implementation Requirements

**Hardware**
- TPM 2.0 chip
- YubiKey with PIV support
- Standard x86/ARM processor

**Software**
- Emercoin blockchain node
- IPFS daemon
- Python 3.8+ runtime
- tpm2-tools package

**Network**
- Internet connectivity for updates
- Yggdrasil mesh (optional)
- Local database cache

## Operational Considerations

**Backup Strategy**
- TPM handles are hardware-specific
- YubiKey can be duplicated for redundancy
- Blockchain provides automatic backup

**Key Rotation**
- Generate new identity components
- Update blockchain record
- Maintain old identity during transition

**Monitoring**
- Transaction logs for audit trail
- Merkle root changes indicate updates
- Domain expiration warnings