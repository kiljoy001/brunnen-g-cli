# Brunnen-G Design Document v2.0

## Architecture Overview

Decentralized PKI using TPM hardware security, Emercoin blockchain persistence, Yggdrasil mesh networking, with enterprise-grade authentication and monitoring.

## Core Design Decisions

### Node Addressing
- **Algorithm**: Blake2b hash of `ygg_pubkey + tpm_pubkey`
- **Encoding**: Base58 (Bitcoin-style)
- **Format**: Single hash combining network + hardware identity
- **Example**: `5KJvsngHeMpm884wtkJNzQGaCErckhHjBGFsvd3VyK5qMZXj3hS`

### TPM Security
- **Handle Generation**: Randomized in range `0x81010000-0x8101FFFF`
- **Metadata Protection**: YubiKey-encrypted using challenge-response
- **Storage**: All sensitive files in `/dev/shm` (memory-only)
- **Key Export**: Never leave TPM hardware
- **WebAuthn Integration**: Domain seeds via platform authenticators

#### Metadata Encryption Design

**Files:**
- `/tpmdata/provisioning.enc` - Encrypted metadata
- `/dev/shm/.brunnen_challenge` - YubiKey challenge (32 bytes hex)
- `/tpmdata/provisioning.hash` - Content hash for change detection
- `/dev/shm/handle.txt` - Temporary handle file

**Encryption Process:**
1. Generate random 32-byte challenge
2. Get YubiKey challenge-response (slot 2, hex mode)
3. Use response as AES-256-CBC key with PBKDF2
4. Encrypt metadata JSON with OpenSSL
5. Store challenge in memory-only filesystem

**Metadata Contents:**
```json
{
  "identities": {
    "user@domain.coin": {
      "tpm_handle": "0x810012DF",
      "created_at": "1234567890",
      "encryption_method": "yubikey_aes"
    }
  },
  "domain_settings": {
    "domain.coin": {
      "seed": "sha256_domain_seed",
      "created_at": 1234567890
    }
  },
  "version": "2.0"
}
```

**Security Properties:**
- Requires physical YubiKey presence for decryption
- Metadata unrecoverable without YubiKey
- Handles randomized to prevent enumeration
- Temporary files in memory only
- Content hash prevents unnecessary re-encryption

### Database Schema

#### Core Tables

**address_keys**
```sql
CREATE TABLE address_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL UNIQUE,     -- user@domain.coin
    pubkey TEXT NOT NULL,             -- TPM public key (hex)
    TPM_key TEXT,                     -- TPM handle
    TPM_enable BOOLEAN DEFAULT 1,     -- TPM required flag
    yubikey_hash TEXT DEFAULT '',     -- YubiKey cert hash
    row_hash BLOB                     -- SHA256 of row data
);
```

**domain_settings**
```sql
CREATE TABLE domain_settings (
    domain TEXT PRIMARY KEY,
    owner_address TEXT,               -- Blockchain address
    verified_at INTEGER               -- Timestamp of last verification
);
```

**api_keys**
```sql
CREATE TABLE api_keys (
    app_name TEXT PRIMARY KEY,
    api_key TEXT NOT NULL,            -- SHA256 hash
    permissions TEXT DEFAULT 'read',   -- Comma-separated
    created_at INTEGER,
    last_used INTEGER
);
```

**voip_endpoints**
```sql
CREATE TABLE voip_endpoints (
    address TEXT PRIMARY KEY,
    sip_uri TEXT,                     -- Direct SIP URI
    ygg_address TEXT,                 -- Yggdrasil IPv6
    created_at INTEGER
);
```

**storage_refs**
```sql
CREATE TABLE storage_refs (
    id TEXT PRIMARY KEY,              -- SHA256 of content
    type TEXT NOT NULL,               -- cbor|ipfs|bt
    ref TEXT NOT NULL,                -- Storage reference
    size INTEGER,
    created_at INTEGER
);
```

#### Integrity Process
1. Each row gets `row_hash = sha256(concatenated_fields)`
2. Table merkle root computed from all row hashes
3. Final database root from all table roots
4. Published to blockchain as `trust:domain.coin`

## Blockchain Records

### Domain Records
```
dns:domain.coin = {
  "AAAA": "200:1234::abcd",  // Yggdrasil IPv6
  "trust": {
    "cid": "QmHash...",
    "merkle_root": "abc123..."
  },
  "other_dns_records": "..."
}
```

### Group Registry
```
registry:domain.coin:88815158 = {
  "members": ["user_tpm_hash1", "user_tpm_hash2"],
  "nodes": ["blake2b_base58_address1", "blake2b_base58_address2"],
  "owner": "domain_owner_address", 
  "group_id": 88815158,
  "allow_any_device": false,
  "merkle_root": "data_integrity_hash"
}
```

### Data Storage
```
risk:small_config = "A2646E616D65664461766964646167656418"  // CBOR data <15KB

risk:medium_file = "ipfs:QmV8cfu6n4NT5xRr6AuvLs7PiLoXf7q8VDdV7qJj8x8x"  // IPFS CID <5GB

risk:large_dataset = "A2677472616E6B657273...746F7272656E74"  // CBOR{tracker, torrent_data} >5GB
```

## Storage Tiers

1. **CBOR** (<15KB): Direct blockchain storage
   - API keys, configs, certificates
   - Incident reports, signatures
   - Small JSON documents

2. **IPFS** (<5GB): Distributed hash-addressed
   - VM images, container images
   - Code repositories
   - Documentation, forensic data

3. **BitTorrent** (>5GB): P2P distribution
   - System backups
   - Video archives
   - Large database dumps

## Authentication Stack

### PAM Module
- **File**: `pam_brunnen_g.so`
- **Integration**: `/etc/pam.d/common-auth`
- **Flow**: Username → API verify → TPM challenge → Success
- **Features**: 
  - YubiKey OTP support
  - Offline cache capability
  - Group membership sync

### WebAuthn Domain Seeds
- **Endpoint**: `http://localhost:8888`
- **Storage**: TPM-sealed with PCR policy
- **Purpose**: Hardware-backed domain identity
- **Recovery**: Requires same TPM + PCR state

## Network Architecture

### Yggdrasil Integration
- TPM-secured private keys
- Auto-start with systemd
- Mesh routing for global reach
- IPv6 addresses for all services

### VoIP Integration
- **Protocol**: SIP over Yggdrasil
- **Dialing**: `user@domain.coin`
- **AGI Script**: `brunnen_lookup.agi`
- **Fallback**: PSTN via E.164 mapping

### API Design
- **Port**: 8080 (configurable)
- **Auth**: HMAC-SHA256 signatures
- **Rate Limiting**: Per-app configurable
- **Monitoring**: Wazuh integration

## Monitoring & Security

### Wazuh SIEM Integration
- **Events**: Identity ops, API access, TPM operations
- **Socket**: `/var/ossec/queue/ossec/queue`
- **Format**: JSON with rule metadata
- **Dashboard**: Real-time security monitoring

### Security Hardening
- Mandatory TPM 2.0
- YubiKey for metadata protection
- Memory-only sensitive files
- Automatic cleanup on exit
- Secure random from TPM

## API Endpoints

### Public
- `GET /api/v1/health` - System status
- `GET /api/v1/query?address=user@domain.coin` - User lookup
- `GET /api/v1/verify?address=user@domain.coin` - Identity verification

### Authenticated
- `POST /api/v1/register` - Identity registration
- `POST /api/v1/sign` - TPM signing
- `POST /api/v1/verify-signature` - Signature verification
- `GET /api/v1/metrics` - Usage statistics (admin)
- `POST /api/v1/admin/keys` - API key management (admin)

### Storage
- `POST /api/v1/storage/store` - Store with auto-tiering
- `GET /api/v1/storage/retrieve?ref=...` - Retrieve by reference
- `GET /api/v1/voip/lookup?identity=...` - VoIP endpoint lookup

## Development Status

### Phase 1 (Complete)
- ✓ Core identity registration
- ✓ TPM integration with randomized handles
- ✓ YubiKey metadata encryption
- ✓ Database operations with merkle trees
- ✓ Basic REST API with HMAC auth
- ✓ Tiered storage (CBOR/IPFS/BitTorrent)

### Phase 2 (In Progress)
- ✓ PAM module implementation
- ✓ WebAuthn domain seeds
- ✓ VoIP/Asterisk integration
- ✓ Wazuh SIEM monitoring
- ◯ Group registry implementation
- ◯ Cross-machine synchronization

### Phase 3 (Planned)
- ◯ Enterprise SSO (Keycloak)
- ◯ Web UI improvements
- ◯ Mobile app support
- ◯ Hardware token provisioning
- ◯ Compliance reporting

## Operational Procedures

### Backup & Recovery
1. Export encrypted metadata: `cp /tpmdata/provisioning.enc backup/`
2. Save YubiKey serial/slot config
3. Document TPM handles
4. Blockchain automatic backup via peers

### Key Rotation
1. Generate new TPM handle
2. Update address_keys table
3. Re-sign with domain key
4. Publish new merkle root
5. Keep old handle for transition

### Domain Expiration Monitoring
- Check: `emercoin-cli name_show "dns:domain.coin"`
- Alert threshold: 30 days
- Auto-renewal via API (planned)

## File Structure
```
brunnen-g-cli/
├── brunnen-cli.sh              # Main CLI interface
├── api_daemon.py               # REST API server
├── webauthn_seed.py           # WebAuthn server
├── wazuh_monitor.py           # SIEM integration
├── data/                      # Local databases
│   └── *.db                   # Named by hostname hash
├── tpmdata/                   # TPM metadata
│   ├── provisioning.enc       # YubiKey-encrypted
│   └── provisioning.hash      # Content hash
├── tpm/                       # TPM utilities
│   └── tpm_provisioning.sh    # Handle generation
├── pam/                       # PAM module
│   ├── pam_brunnen_g.c       # Source code
│   └── Makefile              # Build system
├── web/                       # Web interface
│   └── brunnen-g.html        # Agregore UI
└── DESIGN.md                  # This document
```

## Dependencies

### Required
- TPM 2.0 hardware with tpm2-tools
- YubiKey with challenge-response
- Emercoin node with RPC access
- Python 3.8+ with pip packages:
  - flask, fido2, cryptography
  - requests, sqlite3, cbor2
- Yggdrasil mesh daemon
- IPFS daemon

### Optional
- Wazuh agent for monitoring
- Asterisk for VoIP
- BitTorrent client (transmission)
- Keycloak for enterprise SSO

## Performance Targets

- Identity verification: <100ms local, <500ms remote
- TPM operations: <200ms signing, <300ms verification  
- API response time: <50ms cached, <200ms uncached
- Database sync: <10s for 10k identities
- Storage tier selection: Automatic based on size

## Future Enhancements

### Technical Roadmap
- [ ] HSM support for enterprise
- [ ] Post-quantum crypto readiness
- [ ] Distributed database sync protocol
- [ ] Zero-knowledge proofs for privacy
- [ ] Smart contract automation

### Integration Targets
- [ ] Active Directory federation
- [ ] LDAP/RADIUS compatibility
- [ ] OAuth2/OIDC provider
- [ ] Kubernetes admission control
- [ ] CI/CD pipeline integration