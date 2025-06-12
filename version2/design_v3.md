# Brunnen-G Identity System Documentation v3.1

## Overview

Brunnen-G implements a decentralized public key infrastructure using hardware security modules, blockchain persistence, and certificate-based identity storage. The system enables passwordless authentication without central authorities or network dependencies.

## Core Identity Equation

Each identity is computed as a stable hash:
```
Let:
 H(.) denote the SHA256 hash function
 || denote the concatenation operator
 TPMpk represents the TPM public key
 DILsig represents the Dilithium signature of the Emercoin signed hash of TPMpk
 YUBIpk represents the YubiKey public key in slot 9c (touch-only)

First define the Domain Identity Hash (DIH):
 DIH = H(TPMpk || H(DILsig))

Then, the Stable Identity Hash (IDstable):
 IDstable = H(DIH || H(YUBIpk))

IDstable serves as the leaf in merkle trees, providing an unchanging identifier.
```

### Components

**TPM Public Key**
- Hardware-generated key that never leaves the TPM
- Provides root of trust anchored in silicon
- Randomized handles prevent enumeration

**Emercoin Domain Signature**
- Proves domain ownership through blockchain
- Signs the TPM public key with domain's private key
- Creates binding between hardware and blockchain identity

**Dilithium Signature**
- Post-quantum cryptographic signature
- Signs the Emercoin signature for quantum resistance
- NIST-approved algorithm (FIPS 204)

**YubiKey Component**
- PIV slot 9c configured for touch-only (no PIN)
- Certificate generated on-device with custom extensions
- Physical touch required for all operations
- Public key exportable for remote verification

## Certificate-Based Architecture

### Self-Contained Identity

X.509 certificate structure:
- **Subject**: user@domain.coin
- **Extension OID 63716**: Merkle proof and metadata (JSON)
  - merkle_proof: array of proof nodes
  - merkle_index: leaf position
  - dih: Domain Identity Hash
  - domain_signature: Emercoin signature

### Multi-Slot Device Identity
Slots could be used to hold multiple idenities, typically for devices that the user may have using the yggdrasil public key as an identifier. An extension equation of IDstable = H(DIH || H(YUBIpk) || H(YggPubKey))
- **Slot 9a**: Personal device identity
- **Slot 9c**: Work device identity  
- **Slot 9d**: Kiosk/shared device identity
- **Slot 9e**: Service-specific identity

Each slot binds a user to a specific device, enabling fine-grained access control.

## Registration Process

### Step 1: Identity Generation
1. TPM generates keypair (randomized handle)
2. Domain owner signs TPM public key with Emercoin key
3. Dilithium signs the domain signature
4. YubiKey generates touch-only key in slot 9c

### Step 2: Certificate Creation
1. Compute IDstable for user
2. Add user to domain's merkle tree
3. Generate merkle proof for user
4. YubiKey generates certificate with proof in extension
5. Certificate remains on YubiKey

### Step 3: Domain Publication
1. Compute final merkle root
2. Publish to blockchain:
   ```
   trust:domain.coin = {
     "merkle_root": "0xabc123...",
     "blockheight": 1234567890
   }
   ```

## Authentication Flow

### Touch-Only Authentication
1. Verifier sends challenge nonce
2. User signs challenge with YubiKey (touch required)
3. Verifier validates signature with certificate public key
4. Extract merkle proof from certificate extension
5. Verify proof against blockchain merkle root

This order prevents proof replay attacks by validating possession first.

### Cross-Domain Verification

User alice@domain1.coin authenticates to domain2.coin:
1. domain2.coin generates challenge
2. alice signs with YubiKey from domain1.coin
3. domain2.coin fetches trust:domain1.coin from blockchain
4. Verifies alice's merkle proof against domain1's root
5. Grants access based on domain trust policies

## Data Layer (Prefix: 'risk:')

### Storage Tiers
1. **CBOR on Blockchain** (<15KB)
   - Direct storage with 'risk:' prefix
   - Configuration, metadata, small files
   - Example: `risk:domain.coin:config`

2. **BitTorrent** (>15KB)
   - Large databases, media files
   - Blockchain stores torrent hash
   - P2P distribution for scalability

## API Design

### DDOS Protection

Verify endpoints protected via:
- Rate limiting per IP/identity
- Proof-of-work challenges for anonymous access
- YubiKey signature validation before expensive operations
- Caching of recently verified identities

### Core Endpoints
```
GET  /api/v1/health              - System status
POST /api/v1/auth/challenge      - Get auth challenge
POST /api/v1/auth/verify         - Verify signed challenge
POST /api/v1/register            - Register new identity (authenticated)
```

## Security Properties

**Hardware Binding**
- Private keys physically locked in TPM/YubiKey
- Touch requirement prevents automation
- Survives OS compromise

**Quantum Resistance**
- Dilithium signatures resist quantum attacks
- SHA256 provides 128-bit quantum security
- Forward-secure design

**Physical Presence**
- Every operation requires touch
- No PIN reduces phishing surface
- Rate-limited by human interaction

**Offline Capability**
- Certificate contains all verification data
- Only blockchain root lookup required
- Works with cached merkle roots

## Network Architecture

### Yggdrasil Integration
- TPM-secured mesh networking
- Cryptographic device addressing
- Direct peer-to-peer identity verification
- IPv6 addresses for all nodes

## Database Role

Databases used only for:
- Initial merkle tree computation
- Batch registration processing
- Administrative operations

Not required for:
- Identity verification
- Authentication
- Certificate validation

## Group Membership

Blockchain registry for group management:
```
registry:domain.coin:groupID = {
  "members": ["alice_IDstable", "bob_IDstable"],
  "merkle_root": "0xdef456...",
  "updated": 1234567890
}
```

## Speculative Features

### Hardware Anti-Theft
- Device requires specific identity to boot
- TPM + YubiKey binding for unlock
- BIOS/UEFI integration potential

### LoRaWAN Integration
- Offline mesh networking
- Disaster-resilient communication
- Identity verification over radio

### Machine Identity
- Yggdrasil public key as machine identity
- Cross-system authentication via mesh
- Service-to-service authentication