# CLI Password Manager

A secure command-line password manager built in Python. Stores encrypted credentials
locally — no cloud, no server, no third-party services.

## Security design
- **PBKDF2-HMAC-SHA256** with 480,000 iterations derives an encryption key from the
  master password — brute-force resistant even on modern hardware
- **Fernet (AES-128-CBC + HMAC-SHA256)** encrypts the entire vault as a single blob —
  an attacker can't see entry count or site names, and any tampering is detected before
  decryption
- **Random 16-byte salt** generated on first run and stored separately from the vault —
  identical master passwords produce different keys across installs
- Passwords are **never stored or logged in plaintext** at any point

## Features
- Add, view, list, and delete credentials by site
- Wrong master password rejected immediately via MAC verification
- Empty input and duplicate entry guards
- Vault and salt files excluded from version control

## Usage
```bash
pip install cryptography
python3 manager.py
```

## Files
- `manager.py` — full application, single file
- `vault.dat` — encrypted vault (auto-created, git-ignored)
- `salt.bin` — key derivation salt (auto-created, git-ignored)

---
Built by Andre, incoming UMass CS '30
