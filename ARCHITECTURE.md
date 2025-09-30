# Lox Architecture - Custom Encryption Protocol

## Overview

Lox implements a **completely custom encryption protocol** with no dependency on GPG or any external key management systems. Everything is derived from a single master password using modern, state-of-the-art cryptographic primitives.

## Why No GPG?

**Problems with GPG:**
- Complex key management
- Old cryptographic algorithms (RSA from 1970s)
- Not designed for password-based encryption
- Large attack surface
- Difficult to use correctly

**Lox's Approach:**
- Single master password (easy to remember, hard to crack)
- Modern post-Snowden cryptography
- Purpose-built for password storage
- Minimal attack surface
- Simple, secure by default

---

## Custom Encryption Protocol

### 1. Master Password → Encryption Keys

```
Master Password (string)
         ↓
    Argon2id KDF
    - Salt: 32 bytes (random, stored per-encryption)
    - Memory: 64 MB
    - Iterations: 3
    - Parallelism: 4 threads
    - Output: 64 bytes
         ↓
    Split into two keys:
    ├─→ ChaCha20 Key (32 bytes)
    └─→ AES-256 Key (32 bytes)
```

**Why Argon2id?**
- Winner of Password Hashing Competition (2015)
- Memory-hard: requires 64 MB RAM, defeating GPU/ASIC attacks
- Hybrid of Argon2i (side-channel resistant) and Argon2d (GPU resistant)
- OWASP recommended for password storage
- Better than PBKDF2, bcrypt, or scrypt

### 2. Double-Layer Encryption

```
Plaintext Password/Data
         ↓
┌────────────────────────────────┐
│  Layer 1: ChaCha20-Poly1305    │
│  - Nonce: 12 bytes (random)    │
│  - Key: 32 bytes (from Argon2) │
│  - Output: Ciphertext + 16-byte MAC
└────────────────────────────────┘
         ↓
    Encrypted Data
         ↓
┌────────────────────────────────┐
│  Layer 2: AES-256-GCM          │
│  - Nonce: 12 bytes (random)    │
│  - Key: 32 bytes (from Argon2) │
│  - Output: Ciphertext + 16-byte MAC
└────────────────────────────────┘
         ↓
    Double-Encrypted Data
```

**Why Two Layers?**
- **Defense in Depth**: If one algorithm is broken, the other still protects you
- **Algorithm Diversity**: Different cipher types (stream vs block)
- **Redundant Authentication**: Two independent MAC tags verify integrity
- **Future-Proof**: When quantum computers break one, you still have time

### 3. Storage Format

Each encrypted entry in the SQLite database:

```
Offset  | Size (bytes) | Field
--------|--------------|------------------------
0       | 32           | Argon2 Salt
32      | 12           | ChaCha20 Nonce
44      | 12           | AES-GCM Nonce
56      | variable     | Double-encrypted data
                       | (includes both MAC tags)
```

**Example:**
```
[32B: salt][12B: nonce1][12B: nonce2][data + 2 MACs]
|<-- Key Derivation -->|<-- Encryption Parameters -->|<-- Ciphertext -->|
```

---

## Security Properties

### Confidentiality
✅ **256-bit security** from both ChaCha20 and AES-256  
✅ **No key reuse** - fresh nonces for every encryption  
✅ **Metadata protected** - entry names are encrypted  
✅ **Database encrypted** - no plaintext on disk  

### Integrity
✅ **Authenticated encryption** - Poly1305 and GCM MACs  
✅ **Tampering detected** - any modification fails decryption  
✅ **No malleability** - cannot modify ciphertext meaningfully  

### Authentication
✅ **Password verification** - Argon2 hash stored encrypted  
✅ **Rate limiting** - 5 attempts per 5 minutes  
✅ **Audit logging** - all access recorded (encrypted)  

### Forward Secrecy
⚠️ **Not applicable** - password manager needs deterministic decryption  
✅ **Session timeout** - 5-minute automatic logout  
✅ **No password caching** - master password wiped from memory  

---

## Memory Security

### Secure Memory Wiping

```python
class SecureMemory:
    def wipe(self):
        # DoD 5220.22-M Standard
        for _ in range(3):
            overwrite_with_random()
        overwrite_with_zeros()
        clear_memory()
```

**Protection Against:**
- ✅ Memory dumps
- ✅ Core dumps
- ✅ Swap file leakage
- ✅ Cold boot attacks (partial)
- ✅ Debugging/inspection

**Automatic Wiping:**
- When exiting context managers
- After decryption operations
- On session timeout
- On program exit

---

## Cryptographic Algorithms

### ChaCha20-Poly1305
**Type:** Stream cipher with MAC  
**Designed by:** Daniel J. Bernstein (djb)  
**Year:** 2008  
**Key Size:** 256 bits  
**Security:** 256-bit security level  

**Why ChaCha20?**
- Faster than AES on CPUs without AES-NI
- Simple, constant-time implementation (side-channel resistant)
- No timing attacks
- Used by Google, OpenSSH, Wireguard, TLS 1.3
- Audited extensively

### AES-256-GCM
**Type:** Block cipher in Galois Counter Mode  
**Designed by:** NIST/Rijndael authors  
**Year:** 2001 (AES), 2007 (GCM)  
**Key Size:** 256 bits  
**Security:** 256-bit security level  

**Why AES-GCM?**
- Industry standard, FIPS 140-2 approved
- Hardware acceleration on modern CPUs (AES-NI)
- Authenticated encryption (integrity + confidentiality)
- Parallel encryption/decryption
- Used by: Banking, Military, Government

### Argon2id
**Type:** Password-based key derivation  
**Designed by:** Alex Biryukov, Daniel Dinu, Dmitry Khovratovich  
**Year:** 2015 (PHC winner)  
**Memory:** 64 MB  
**Security:** Memory-hard, GPU/ASIC resistant  

**Why Argon2id?**
- Specifically designed to defeat crackers
- Memory-hard: expensive on any hardware
- Hybrid design: best of Argon2i and Argon2d
- Configurable time/memory/parallelism
- OWASP recommended

---

## Attack Resistance

### Brute Force Attacks
**Protection:** Argon2id + Rate Limiting  
**Cost to Attacker:** ~0.5 seconds per password attempt + 64 MB RAM  
**With Rate Limit:** 5 attempts per 5 minutes  
**Time for 8-char password:** Centuries with modern hardware  

### Dictionary Attacks
**Protection:** Master password strength analysis  
**Minimum:** 8 characters  
**Recommended:** 16+ characters or passphrase  
**Breach Checking:** Warns if password in known breaches  

### Rainbow Tables
**Protection:** Salt (32 bytes random per encryption)  
**Effectiveness:** Impossible - each salt is unique  
**Cost to Attacker:** Must start from scratch for each password  

### Side-Channel Attacks
**Protection:** Constant-time operations  
**ChaCha20:** Naturally constant-time  
**AES-GCM:** Hardware AES-NI (constant-time)  
**Timing:** No timing-based conditionals  

### Quantum Attacks
**Current Status:** Both algorithms quantum-vulnerable (Grover's algorithm)  
**Effective Security:** 128 bits against quantum computers  
**Timeline:** Still secure for decades (no practical quantum computers)  
**Future:** Can add post-quantum layer if needed  

### Memory Attacks
**Protection:** Secure memory wiping  
**Cold Boot:** Partial resistance (wipes after use)  
**DMA:** Use full disk encryption (external to Lox)  
**Core Dumps:** Memory wiped before dumps  

---

## Protocol Flow

### Initialization
```
1. User enters master password
2. Generate random 32-byte salt
3. Derive keys via Argon2id(password, salt)
4. Hash master password with Argon2
5. Encrypt hash with derived keys
6. Store encrypted hash in database
7. Wipe keys from memory
```

### Encryption
```
1. User enters master password
2. Extract salt from previous encryptions
3. Derive keys via Argon2id(password, salt)
4. Generate random ChaCha20 nonce (12 bytes)
5. Encrypt plaintext: ChaCha20(plaintext, key1, nonce1)
6. Generate random AES-GCM nonce (12 bytes)
7. Encrypt ciphertext: AES-GCM(ciphertext1, key2, nonce2)
8. Combine: salt || nonce1 || nonce2 || ciphertext2
9. Store in database
10. Wipe keys and plaintext from memory
```

### Decryption
```
1. User enters master password
2. Extract: salt, nonce1, nonce2, ciphertext from database
3. Derive keys via Argon2id(password, salt)
4. Decrypt layer 2: AES-GCM(ciphertext, key2, nonce2)
5. Verify MAC (fails if wrong password or tampered)
6. Decrypt layer 1: ChaCha20(ciphertext1, key1, nonce1)
7. Verify MAC (second integrity check)
8. Return plaintext
9. Wipe keys and intermediate values from memory
```

---

## Comparison with Other Systems

### vs. `pass` (GPG-based)
| Feature | pass (GPG) | Lox (Custom) |
|---------|-----------|--------------|
| Encryption | RSA + Symmetric | ChaCha20 + AES-256 |
| Key Derivation | None | Argon2id |
| Password-based | No | Yes |
| Layers | 1 | 2 |
| Metadata Protection | No | Yes |
| Memory Wiping | No | Yes |
| Audit Log | No | Yes (encrypted) |

### vs. 1Password/LastPass
| Feature | 1Password | Lox |
|---------|-----------|-----|
| Encryption | AES-256 | ChaCha20 + AES-256 (double) |
| Key Derivation | PBKDF2 | Argon2id (stronger) |
| Storage | Cloud | Local (your control) |
| Open Source | No | Yes (this code) |
| Trust Model | Trust company | Trust yourself |

### vs. KeePass
| Feature | KeePass | Lox |
|---------|---------|-----|
| Encryption | AES-256 or ChaCha20 | Both (layered) |
| Key Derivation | Argon2 | Argon2id |
| Interface | GUI | CLI (faster, scriptable) |
| Metadata | Visible in database | Fully encrypted |
| Audit Log | Basic | Encrypted, detailed |

---

## Security Auditing

### What You Should Audit
1. ✅ **Cryptographic primitives** - Using well-known libraries (cryptography, argon2-cffi)
2. ✅ **Key derivation** - Argon2id with OWASP parameters
3. ✅ **Nonce generation** - Using `secrets` module (CSPRNG)
4. ✅ **Memory handling** - Secure wiping implemented
5. ✅ **Error handling** - No information leakage in exceptions

### What's NOT Implemented (Intentionally)
- ❌ **Network sync** - Keep it local, reduce attack surface
- ❌ **Browser integration** - Use clipboard, no browser extensions
- ❌ **Biometric unlock** - OS-dependent, complexity
- ❌ **Hardware keys** - Can be added as enhancement

---

## Future Enhancements

### Possible Additions
1. **Post-quantum cryptography** - Add Kyber/Dilithium layer
2. **Hardware key support** - YubiKey challenge-response
3. **Threshold encryption** - Split master password (Shamir's Secret Sharing)
4. **Steganography** - Hide vault in innocuous files
5. **Duress password** - Different password wipes/shows decoy data

### Won't Add
- ❌ Cloud sync (security risk)
- ❌ Web interface (attack surface)
- ❌ Password recovery (defeats purpose)
- ❌ Automatic updates (supply chain risk)

---

## References

### Standards & Guidelines
- NIST SP 800-38D: GCM Mode
- NIST SP 800-132: Password-Based Key Derivation
- OWASP Password Storage Cheat Sheet
- DoD 5220.22-M: Data Sanitization

### Cryptographic Papers
- RFC 8439: ChaCha20-Poly1305 AEAD
- RFC 5869: HKDF Key Derivation
- Argon2 Paper: https://github.com/P-H-C/phc-winner-argon2
- DJ Bernstein: ChaCha20 Design

### Libraries Used
- `cryptography` (PyCA): https://cryptography.io/
- `argon2-cffi`: https://argon2-cffi.readthedocs.io/
- `pynacl` (libsodium): https://pynacl.readthedocs.io/

---

## Disclaimer

**This is a custom cryptographic protocol.** While it uses well-established primitives (ChaCha20, AES, Argon2), the combination and implementation is custom. 

**Recommendations:**
- ✅ Use for personal password management
- ✅ Keep master password strong
- ✅ Make regular encrypted backups
- ✅ Use full disk encryption
- ⚠️ Consider professional audit for business use
- ⚠️ No warranty provided (see LICENSE)

**Remember:** Even the best encryption is useless if your master password is "password123"!

---

**Made with 🔐 by developers who don't trust GPG**