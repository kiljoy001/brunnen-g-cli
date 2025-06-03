# Brunnen-G CLI

**Decentralized Public Key Infrastructure for a Secure Internet Future**

Brunnen-G is a security-first framework for identity, data, and communication built around TPM-sealed hardware keys, YubiKey bearer tokens, blockchain anchoring, and peer-to-peer networking. Its mission: stop digital abuse with physical cost, turning security from a liability into an economic advantage.

---

## ⚖️ Vision

A self-defending network infrastructure where:

* Identity is rooted in hardware, not servers
* Abuse incurs real-world cost (energy, time, or crypto)
* Institutions manage complexity; individuals retain freedom
* The network gets stronger with every attack

---

## 📈 Development Status

### Phase 1 – Core Infrastructure (75%)

* ✅ TPM 2.0 integration (randomized handle model)
* ✅ YubiKey token enforcement for every user
* ✅ SQLite + Merkle Tree DB with TPM-sealed root
* ✅ Emercoin blockchain anchoring for domain identities
* ✅ Yggdrasil mesh networking with address verification
* ☐ Full registration menu finalization
* ☐ VoIP economic spam deterrence (in progress)

### Phase 2 – Economic Defense & Integration (Q3 2025)

* ☐ Dynamic EMC pricing tied to activity (VoIP, auth, etc)
* ☐ Do-Not-Disturb mode with fee-based access override
* ☐ Per-block expiry for Yggdrasil identity presence
* ☐ TPM-sealed audit logs
* ☐ Attack income reporting (per domain)
* ☐ PAM module integration for hardware-bound login
* ☐ Data layer with CBOR/IPFS/BitTorrent tiered storage
* ☐ Distributed group management system (blockchain anchored)
* ☐ Web-based interface for identity and domain management
* ☐ Keycloak integration for enterprise SSO support (named integration)

### Phase 3 – Expansion (Q4 2025)

* VoIP dial-by-identity (uses API-based EMC spam defense model via Asterisk)
* Optional DID integration for standards compliance
* Web interface (with YubiKey support)
* IPFS + CBOR data upload with economic anti-spam

### Phase 4 – Ecosystem (2026)

* Mobile CLI + identity sync
* Enterprise domain profit dashboards
* Integrations (email, auth, chat)

---

## 🌐 Core Architecture

```
Users        ───>    CLI Menu (no flags, no scripts)
                          │
                          ▼
TPM 2.0 ─── SQLite DB ─── Merkle Tree ──> Sealed Root in TPM
    │                       │
    ▼                       ▼
YubiKey <───── Identity Binding ───── Emercoin Blockchain
    │
    ▼
Yggdrasil Public Key (registered w/ expiration)
    │
    ▼
LoRa Radio (optional offline routing)
```

### Key Design Rules

* **LoRa fallback**: Optional mesh routing via LoRa for offline/disaster scenarios
* **No scripting**: Menu interaction only to prevent automation
* **Clean CLI**: No emojis or UI tricks in terminal output
* **No `attack:` records**: Abuse tracked via expiring Yggdrasil keys

---

## 🔐 Security Model

* TPM-sealed keys: Private keys never leave hardware
* YubiKey tokens: Mandatory for every identity
* Merkle-sealed SQLite: Integrity-checked, sealed on schedule or change
* Per-block expiration: Ygg keys expire after randomized timeouts
* Economic deterrence: Cost scales with attack intensity

---

## 📅 Registration Flow

* **Interactive menu**: No flags, fully guided process
* **No platform fee**: Registration only incurs Emercoin NVS fee
* **YubiKey required**: Proof-of-ownership at registration
* **Fee scaling**: Exponential EMC costs discourage abuse
* **Admin verification**: Identity binding must be approved per domain

---

## 📊 Economic Defense

All services (registration, VoIP, messaging, etc.) are governed by a shared, API-based economic defense mechanism:

### Exponential Cost Formula

* **Base**: 0.01 EMC
* **Fee** = 0.01 EMC × 2^n (n = number of recent attempts)

**Examples**:

* 1st attempt → 0.01 EMC
* 5th attempt → 0.32 EMC
* 10th → 10.24 EMC
* 15th → 327.68 EMC

### "Do Not Disturb" (DND) Mode

* All incoming actions require EMC
* Fee scales dynamically during DND
* Caller pays, receiver earns

```bash
# View current cost
./brunnen-cli.sh
> Domain: bank.coin
> Current fee: 2.56 EMC
```

---

## ⚙️ Requirements

### Hardware

* TPM 2.0 chip (required)
* YubiKey (FIDO2-compatible, required)

### Software

```bash
sudo apt install tpm2-tools sqlite3 python3 golang-go git
pip3 install requests cryptography cbor2 systemd-python
```

---

## 🔧 Installation

Brunnen-G minimizes blockchain overhead via **batch publishing**:

* **Default**: 24-hour cron job posts updates
* **Manual**: Trigger publish from CLI

Steps:

1. Install Emercoin (RPC optional)
2. Start Emercoin daemon
3. Install & configure Yggdrasil
4. Initialize TPM
5. Launch CLI

```bash
./brunnen-cli.sh
```

---

## 👁️ Usage (CLI Only)

```bash
./brunnen-cli.sh
> Register Identity
> Requires: TPM + YubiKey + Domain Admin Approval
```

### CLI Menu Categories

**Identity & Crypto**

* Query user
* Sign message
* Verify signature
* Publish to blockchain
* Create / List / Revoke

**VoIP & Messaging**

* Configure VoIP
* Send message (coming soon)

**System & API Ops**

* Manage API keys
* DB operations
* Export DB
* Backup to IPFS

**Monitoring & Audit**

* Enable/Disable Wazuh
* Status & connection tests

**TPM Tools**

* TPM maintenance
* View TPM handles
* Merkle root audit
* Encrypt/decrypt tests

---

## 👤 File Structure

```
brunnen-g-cli/
├── brunnen-cli.sh
├── api_daemon.py
├── api_db/
│   ├── api.db
│   ├── merkle_hashes/
│   └── sealed_root.bin
├── tpm/
├── yggdrasil-tpm-startup.sh
└── docs/
```

---

## 🚫 Security Notice

**Brunnen-G is alpha software. Not production-ready.**

* All identities are public
* Loss of private key = total loss
* EMC cost for registration varies
* API access requires Ygg key (visible on-chain)

---

## 📄 License

AGPL-3.0 License

---

**Built for defense. Owned by no one. Enforced by math.**
