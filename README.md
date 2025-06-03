# Brunnen-G CLI

**Decentralized Public Key Infrastructure for a Secure Internet Future**

Brunnen-G is a security-first framework for identity, data, and communication built on TPM-sealed hardware keys, YubiKey bearer tokens, blockchain anchoring, and peer-to-peer networking. It transforms security from a liability into an economic advantage by imposing real-world costs on digital abuse.

## Vision

Building a self-defending network infrastructure where:
- Identity is rooted in hardware, not servers
- Abuse incurs real-world cost (energy, time, or cryptocurrency)
- Institutions manage complexity while individuals retain freedom
- The network strengthens with every attack

## Development Status

### Phase 1: Core Infrastructure (75% Complete)
- ✅ TPM 2.0 integration with randomized handle model
- ✅ YubiKey token enforcement for all users
- ✅ SQLite + Merkle Tree database with TPM-sealed root
- ✅ Emercoin blockchain anchoring for domain identities
- ✅ Yggdrasil mesh networking with address verification
- ⏳ Full registration menu finalization
- ⏳ VoIP economic spam deterrence

### Phase 2: Economic Defense & Integration (Q3 2025)
- Dynamic EMC pricing tied to activity
- Do-Not-Disturb mode with fee-based access override
- Per-block expiry for Yggdrasil identity presence
- TPM-sealed audit logs
- Attack income reporting per domain
- PAM module for hardware-bound login
- Data layer with CBOR/IPFS/BitTorrent tiered storage
- Distributed group management (blockchain anchored)
- Web-based identity and domain management interface
- Keycloak integration for enterprise SSO support

### Phase 3: Expansion (Q4 2025)
- VoIP dial-by-identity with API-based EMC spam defense
- DID integration for standards compliance
- Web interface with YubiKey support
- IPFS + CBOR data upload with economic anti-spam

### Phase 4: Ecosystem (2026)
- Mobile CLI and identity sync
- Enterprise domain profit dashboards
- Integration with email, auth, and chat systems

## Core Architecture

```
Users ──────> CLI Menu (no flags, no scripts)
                    │
                    ▼
TPM 2.0 ─── SQLite DB ─── Merkle Tree ──> Sealed Root in TPM
    │                       │
    ▼                       ▼
YubiKey <─── Identity Binding ─── Emercoin Blockchain
    │
    ▼
Yggdrasil Public Key (registered w/ expiration)
    │
    ▼
LoRa Radio (optional offline routing)
```

### Design Principles
- **LoRa fallback**: Optional mesh routing for offline/disaster scenarios
- **No scripting**: Menu interaction only to prevent automation
- **Clean CLI**: No emojis or UI decoration in terminal output
- **No attack records**: Abuse tracked via expiring Yggdrasil keys

## Security Model

- **TPM-sealed keys**: Private keys never leave hardware
- **YubiKey tokens**: Mandatory for every identity
- **Merkle-sealed SQLite**: Integrity-checked, sealed on schedule or change
- **Per-block expiration**: Yggdrasil keys expire after randomized timeouts
- **Economic deterrence**: Cost scales with attack intensity

## Registration Flow

- Interactive menu-driven process (no command flags)
- No platform fee (only Emercoin NVS fee)
- YubiKey required for proof-of-ownership
- Exponential EMC cost scaling to discourage abuse
- Admin verification required for identity binding

## Economic Defense

All services use shared API-based economic defense:

### Exponential Cost Formula
- Base: 0.01 EMC
- Fee = 0.01 EMC × 2^n (n = number of recent attempts)

Examples:
- 1st attempt: 0.01 EMC
- 5th attempt: 0.32 EMC
- 10th attempt: 10.24 EMC
- 15th attempt: 327.68 EMC

### Do Not Disturb (DND) Mode
- All incoming actions require EMC payment
- Fees scale dynamically during DND
- Caller pays, receiver earns

## Requirements

### Hardware
- TPM 2.0 chip (required)
- YubiKey with FIDO2 support (required)
- LoRa radio (optional)

### Software
```bash
sudo apt install tpm2-tools sqlite3 python3 golang-go git
pip3 install requests cryptography cbor2 systemd-python
```

### Blockchain
- Emercoin daemon (full node or RPC access)
- Yggdrasil mesh networking

## Installation

1. Install and configure Emercoin
2. Start Emercoin daemon
3. Install and configure Yggdrasil
4. Initialize TPM
5. Clone repository and run:

```bash
./brunnen-cli.sh
```

Batch publishing minimizes blockchain overhead (default: 24-hour cron job).

## Usage

```bash
./brunnen-cli.sh
```

### Main Menu Options

**Identity & Crypto**
- Query user
- Sign message
- Verify signature
- Publish to blockchain

**Network & Communication**
- Configure VoIP
- Send message (coming soon)

**Advanced Settings**
- Manage API keys
- Database operations
- TPM maintenance
- Wazuh monitoring

## File Structure

```
brunnen-g-cli/
├── brunnen-cli.sh          # Main CLI interface
├── api_daemon.py           # REST API server
├── data/                   # Database directory
│   └── *.db               # Domain-specific databases
├── tpmdata/               # TPM sealed data
│   └── provisioning.enc   # Encrypted identity metadata
├── tpm/                   # TPM utility scripts
├── yggdrasil-tpm-startup.sh
└── docs/                  # Documentation
```

## Security Notice

**Brunnen-G is alpha software - NOT production ready**

- All identities are public on blockchain
- Loss of private key results in total identity loss
- EMC costs vary with network conditions
- API access requires Yggdrasil key (visible on-chain)

## Contributing

Contributions welcome. Please review security considerations before submitting PRs.

## License

AGPL-3.0 License

---

**Built for defense. Owned by no one. Enforced by math.**