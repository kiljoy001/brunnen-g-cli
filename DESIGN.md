# Brunnen-G Design Document

## Architecture Overview

Decentralized PKI using TPM hardware security, Emercoin blockchain persistence, and Yggdrasil mesh networking.

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

#### Metadata Encryption Design

**Files:**
- `/tpmdata/provisioning.enc` - Encrypted metadata
- `/tpmdata/.challenge` - YubiKey challenge (32 bytes hex)
- `/dev/shm/handle.txt` - Temporary handle file

**Encryption Process:**
1. Generate random 32-byte challenge
2. Get YubiKey challenge-response (slot 2, hex mode)
3. Use response as AES-256-CBC key
4. Encrypt metadata JSON with OpenSSL
5. Store challenge file separately

**Metadata Contents:**
```json
{
  "primary_handle": "0x81001234",
  "key_handle": "0x81005678", 
  "created_at": 1234567890,
  "version": "1.0",
  "randomized": true
}
```

**Security Properties:**
- Requires physical YubiKey presence for decryption
- Metadata unrecoverable without YubiKey
- Handles randomized to prevent enumeration
- Temporary files in memory only

### Database Schema
- **Local DB**: SQLite with merkle tree verification
- **API DB**: Separate database for API keys/settings
- **Naming**: Hash of `hostname + username` for obfuscation

#### Core Tables

**address_keys**
```sql
CREATE TABLE address_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL UNIQUE,     -- user@domain.coin
    pubkey TEXT NOT NULL,             -- TPM public key (hex)
    tmp_key TEXT,                     -- Node TPM public key
    TPM_enable BOOLEAN DEFAULT 1,     -- TPM required flag
    yubikey_hash TEXT DEFAULT '',     -- YubiKey cert hash
    row_hash BLOB                     -- SHA256 of row data
);
```

**db_root** 
```sql
CREATE TABLE db_root (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,         -- Target table name
    root BLOB NOT NULL,               -- Merkle root hash
    row_hash BLOB                     -- Hash of this record
);
```
*Purpose: Stores merkle tree roots for data integrity verification. Each table gets a merkle root computed from all row hashes, enabling cryptographic proof of database state.*

**tpm_domain_settings**
```sql
CREATE TABLE tmp_domain_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,     -- domain.coin
    TPM_enable BOOLEAN DEFAULT 1,    -- Domain TPM policy
    row_hash BLOB                     -- SHA256 of row data
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
  "other_dns_records": "..."
}

trust:domain.coin = {
  "cid": "QmHash...",
  "merkle_root": "abc123..."
}
```

### Group Registry
```
registry:domain.coin:88815158 = {
  "members": ["user_tmp_hash1", "user_tpm_hash2"],
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

**Use Cases by Tier:**
- **CBOR**: API keys, configs, incident reports, contact info
- **IPFS**: VM images, code repos, forensic data, ML datasets  
- **BitTorrent**: System backups, video archives, database dumps

**Advantages**: No vendor lock-in, immutable timestamps, global accessibility, cost-effective for large files, cryptographic proof of existence.

## Storage Tiers

1. **CBOR**: Small data (<15KB) directly on blockchain
2. **IPFS**: Medium files (<5GB) with CID references
3. **BitTorrent**: Large files (>5GB) with torrent hashes

## Zero-Trust Model

### Authentication Requirements
- User identity verification (TPM-backed)
- Machine verification (node address)
- Domain ownership validation
- Group membership confirmation

### Group Permissions
- Domain owner controls membership
- Per-group device restriction settings
- Cross-machine synchronization via blockchain
- PAM integration for local group creation

## Network Architecture

### Yggdrasil Integration
- TPM-secured private keys for network identity
- Mesh routing for global connectivity
- IPv6 addresses for peer communication

### API Design
- Read-only public endpoints
- Admin functions require authentication
- Rate limiting by application/IP
- HMAC request signing

## Development Phases

### Phase 1 (Current)
- Core identity registration
- TPM integration
- Database operations
- Basic API

### Phase 2 
- PAM module
- Group registry implementation
- Data layer (CBOR/IPFS/BitTorrent)
- Cross-machine synchronization

### Phase 3
- Enterprise features
- Wazuh SIEM integration
- Web interface polishing

## Security Considerations

### Hardware Requirements
- TPM 2.0 mandatory
- YubiKey mandatory for metadata encryption
- Secure boot recommended

### Operational Security
- Regular backup of encrypted metadata
- Domain expiration monitoring
- Key rotation procedures
- Audit logging

### Privacy Model
- Public: Domain registrations, group memberships
- Private: User data, TPM keys, metadata
- Semi-private: Network addresses (visible to Ygg peers)

## Open Questions

### Technical
- [ ] PAM module integration approach
- [ ] VoIP SIP integration details  
- [ ] Certificate chain validation
- [ ] Group permission inheritance

### Operational
- [ ] Key recovery procedures
- [ ] Multi-domain federation
- [ ] Performance benchmarks
- [ ] Backup/restore workflows

## API Endpoints

### Public
- `GET /api/v1/health` - System status
- `GET /api/v1/query?address=user@domain.coin` - User lookup

### Authenticated  
- `GET /api/v1/metrics` - Usage statistics (admin)
- `POST /api/v1/admin/keys` - API key management (admin)

## File Structure
```
brunnen-g-cli/
├── brunnen-cli.sh              # Main interface
├── api_daemon.py               # REST API
├── data/                       # Local databases  
├── tmp/                        # TPM utilities
├── PAM/                        # Authentication module
├── web/                        # Web interface
└── DESIGN.md                   # This document
```

## Dependencies

### Required
- TPM 2.0 hardware
- YubiKey hardware token
- Emercoin node with CLI access
- Python 3.8+ with systemd-python
- Go 1.19+ for Yggdrasil
- IPFS daemon
- BitTorrent client/tracker (transmission-daemon or qBittorrent)

### Optional
- Wazuh for monitoring
- Keycloak integration for enterprise SSO