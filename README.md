# Brunnen-G CLI

**Decentralized Public Key Infrastructure using TPM hardware security**

Brunnen-G provides secure identity management through TPM-secured keys, blockchain persistence via Emercoin, and distributed networking with Yggdrasil.

## Core Features

- **TPM 2.0 Integration**: Hardware-secured private key storage
- **Emercoin Blockchain**: Persistent identity and domain ownership verification  
- **Yggdrasil Networking**: Mesh networking for global connectivity
- **SQLite Database**: Local identity caching with merkle tree verification
- **REST API**: Programmatic access for integration
- **Blockchain Storage**: "risk:" prefix for data, "trust:" for key DB with merkle proofs
- **Domain-Based Authentication**: Blockchain ownership provides write authority
- **YubiKey Support**: Hardware authentication tokens (recommended)

## Requirements

### Hardware
- TPM 2.0 chip (required)
- YubiKey (optional)

### Software Dependencies
```bash
# Core requirements
sudo apt install tpm2-tools sqlite3 python3 golang-go git

# Emercoin (REQUIRED)
# Download from https://emercoin.com/downloads/
# Configure with RPC enabled

# Python packages
pip3 install sqlite3 requests cryptography cbor2
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

# Enable DNS services
emcdns=1
emcdnsallowed=.coin|.emc|.lib|.bazar
emcdnsverbose=4
```

2. **Start Emercoin daemon**
```bash
emercoind -daemon
# Wait for blockchain sync: emercoind getinfo
```

3. **Configure DNS resolution**
```bash
# Option 1: Use OpenNIC DNS servers (easiest)
# Set your DNS to: 185.121.177.177, 169.239.202.202

# Option 2: Local DNS proxy (advanced)
# Configure dnsmasq to forward .coin domains to localhost:5335
```

**Full setup guide**: https://emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction/

2. **Install Yggdrasil**
```bash
sudo ./install_yggdrasil.sh
```

3. **Setup TPM**
```bash
# Add user to tss group
sudo usermod -a -G tss $USER
# Log out and back in

# Verify TPM
tpm2_startup -c
tpm2_getcap properties-fixed
```

4. **Initialize Brunnen-G**
```bash
./brunnen-cli.sh
# Choose option 1: Quick Setup
```

## Basic Usage

### Command Line
```bash
# Start CLI
./brunnen-cli.sh

# Register identity (requires domain ownership in Emercoin)
# Menu: 1 → Quick Setup

# Query user
# Menu: 2 → Identity Operations → 1

# Sign data
# Menu: 2 → Identity Operations → 2
```

### API
```bash
# Start API daemon
python3 api_daemon.py

# Register identity
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "domain": "example.coin"}'

# Query user
curl http://localhost:8080/api/v1/query?address=alice@example.coin
```

## Configuration

### Emercoin Setup (REQUIRED)
1. Download Emercoin from official website
2. Configure RPC access in `~/.emercoin/emercoin.conf`
3. Start daemon: `emercoind -daemon`
4. Verify: `emercoin-cli getinfo`

### Environment Variables
```bash
export BRUNNEN_DB_DIR="/var/lib/brunnen"
export API_PORT="8080"
export TPM_DEVICE="/dev/tpm0"
```

## File Structure

```
brunnen-g-cli/
├── brunnen-cli.sh          # Main CLI interface
├── api_daemon.py           # REST API server
├── yggdrasil-tpm-startup.sh # TPM-secured Yggdrasil
├── install_yggdrasil.sh    # Yggdrasil installation
├── web/brunnen-g.html      # Web interface
└── tpm/                    # TPM utilities
```

## Architecture

```
Applications → REST API → Identity Management
                    ↓
TPM 2.0 ← SQLite ← Merkle Trees → Emercoin ("trust:" key DB, "risk:" data)
    ↓                                  ↓
YubiKey ← Yggdrasil Network → IPFS/BitTorrent (large files)
```

## Security Notes

- Private keys never leave TPM hardware
- Emercoin blockchain provides tamper-proof domain ownership
- All database operations use cryptographic verification
- Network traffic encrypted via Yggdrasil mesh

## Dependencies Summary

**Required:**
- TPM 2.0 hardware
- Emercoin blockchain node
- Linux OS with tpm2-tools
- Python 3.8+
- Go 1.19+

**Recommended:**
- YubiKey for enhanced security
- IPFS for distributed storage
- BitTorrent for large file sharing

## License

AGPL-3.0 License
