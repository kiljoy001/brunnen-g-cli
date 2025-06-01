# Brunnen-G CLI

**Decentralized Public Key Infrastructure using TPM hardware security**

Brunnen-G provides secure identity management through TPM-secured keys, blockchain persistence via Emercoin, and distributed networking with Yggdrasil.

## Development Status

**Phase 1 (~60% Complete)**: Core infrastructure and identity management
- ✅ TPM integration, database schema, domain verification
- ⚠️ Identity registration (fixing variable mismatches)
- ❌ PAM module, data layer, enterprise features

## Core Features

### Current
- **TPM 2.0 Integration**: Hardware-secured private key storage with randomized handles
- **Emercoin Blockchain**: Domain ownership verification and trust records
- **Yggdrasil Networking**: Mesh networking for global connectivity  
- **SQLite Database**: Local identity caching with merkle tree verification
- **REST API**: Programmatic access (read-only for security)
- **YubiKey Support**: Hardware authentication tokens and metadata encryption

### Planned (Phase 2)
- **PAM Module**: Linux authentication integration  
- **Group Registry**: Blockchain-stored group memberships with cross-machine sync
- **Data Layer**: CBOR/IPFS/BitTorrent tiered storage with "risk:" prefix

### Enterprise Features (Phase 3)
- **Zero-Trust Authentication**: User + machine TPM verification required
- **Wazuh SIEM**: Security monitoring and threat detection

## Requirements

### Hardware
- TPM 2.0 chip (required)
- YubiKey (required)

### Software Dependencies
```bash
# Core requirements
sudo apt install tpm2-tools sqlite3 python3 golang-go git

# Emercoin (REQUIRED)
# Download from https://emercoin.com/downloads/
# Configure with RPC enabled

# Python packages
pip3 install sqlite3 requests cryptography cbor2 systemd-python

# Optional: Ollama for voice control
curl -fsSL https://ollama.com/install.sh | sh
```

## Installation

1. **Install Emercoin**
```bash
# Download from https://emercoin.com/downloads/
# Configure ~/.emercoin/emercoin.conf with:
rpcuser=your_rpc_user
rpcpassword=your_rpc_password
rpcallowip=127.0.0.1
rpcport=8775
server=1
listen=1
daemon=1
emcdns=1
```

2. **Start Emercoin daemon**
```bash
emercoind -daemon
# Wait for blockchain sync: emercoind getinfo
```

3. **Configure DNS resolution**
```bash
# Option 1: Local Emercoin DNS (recommended)
# Configure router/network to use your node for DNS

# Option 2: OpenNIC DNS servers  
# Set DNS to: 185.121.177.177, 169.239.202.202
```

4. **Install Yggdrasil**
```bash
sudo ./install_yggdrasil.sh
```

5. **Setup TPM**
```bash
# Add user to tss group
sudo usermod -a -G tss $USER
# Log out and back in

# Verify TPM
tpm2_startup -c
tpm2_getcap properties-fixed
```

6. **Initialize Brunnen-G**
```bash
./brunnen-cli.sh
# Choose option 1: Quick Setup
```

## Usage

### Command Line
```bash
# Start CLI
./brunnen-cli.sh

# Hacker mode (enhanced UI)
./brunnen-cli.sh --hacker-mode
```

### API (Read-Only)
```bash
# Start API daemon
python3 api_daemon.py

# Query user (requires API key)
curl -H "X-API-Key: your_key" \
  http://localhost:8080/api/v1/query?address=alice@example.coin

# Health check (public)
curl http://localhost:8080/api/v1/health
```

## Architecture

```
Applications → REST API → Identity Management
                    ↓
TPM 2.0 ← SQLite ← Merkle Trees → Emercoin Blockchain
    ↓              ↓                      ↓
YubiKey ← Yggdrasil Network → IPFS → Group Registry
```

## Blockchain Records

- `dns:domain.coin` - Domain ownership + trust database CID
- `trust:domain.coin` - Identity database with merkle proofs  
- `risk:data_id` - CBOR-encoded data storage
- `registry:domain.coin:group_id` - Group membership with TPM hashes

## Security Model

### Zero-Trust Architecture
- User authentication + machine TPM verification required
- Hardware-bound identity prevents credential theft
- Domain owner controls group membership
- Blockchain provides tamper-proof audit trail

### Privacy Considerations
- Domain registrations are public on Emercoin blockchain
- Yggdrasil traffic visible to mesh peers
- TPM keys never leave hardware
- Group memberships stored on blockchain

## File Structure

```
brunnen-g-cli/
├── brunnen-cli.sh              # Main CLI interface
├── api_daemon.py               # REST API server  
├── yggdrasil-tpm-startup.sh    # TPM-secured Yggdrasil
├── data/                       # Local databases
├── tpm/                        # TPM utilities
│   ├── tpm_provisioning.sh     # Key generation
│   └── *.sh                    # Various TPM tools
├── web/brunnen-g.html          # Web interface
└── PAM/brunnen-g-pam.c         # Linux authentication module
```

## Roadmap

### Phase 1 (Current - Q2 2025)
- Fix identity registration bugs
- Stabilize TPM integration
- Complete API authentication

### Phase 2 (Q3 2025) 
- PAM module deployment
- Distributed group management

### Phase 3 (Q4 2025)
- Enterprise group management
- Wazuh SIEM integration
- Web interface development and polishing

## Security Warnings

### Alpha Software
**Brunnen-G is alpha software. Not for production use.**

### Operational Risks
- Domain loss if private keys compromised
- Blockchain transactions are permanent and public
- Cryptocurrency required for domain registration
- Regular backups essential

### Legal Considerations
- Cryptocurrency usage restrictions vary by jurisdiction
- Decentralized DNS may conflict with regulations
- Users responsible for legal compliance

## License

AGPL-3.0 License