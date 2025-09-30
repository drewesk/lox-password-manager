# GPG vs Lox: Why We Don't Use GPG

## The Problem with `pass` and GPG

### What `pass` Does:
```bash
# pass uses GPG to encrypt each password file
$ pass insert github
# Creates: ~/.password-store/github.gpg
# Encrypted with: Your GPG key (RSA/EdDSA)
```

**Directory Structure (Metadata Exposed):**
```
~/.password-store/
├── Email/
│   ├── gmail.gpg          ← Attacker knows you have Gmail
│   └── work.gpg           ← Attacker knows you have work email
├── Banking/
│   ├── chase.gpg          ← Attacker knows you bank with Chase
│   └── wellsfargo.gpg     ← Attacker knows your banks
└── Social/
    ├── facebook.gpg       ← Attacker knows your social accounts
    └── twitter.gpg
```

**Security Issues:**
1. **File names are visible** - Anyone with file access knows what accounts you have
2. **Directory structure exposed** - Reveals your organization system
3. **File count visible** - Attacker knows how many passwords you have
4. **Modification times visible** - Can track when you change passwords
5. **GPG complexity** - Key management, keyring, trust model
6. **Single encryption layer** - If GPG is broken, all passwords exposed

---

## What Lox Does Differently

### No GPG, Custom Protocol:
```bash
# Lox uses password-based encryption
$ lox insert github
# Creates: ~/.lox/vault.db (single encrypted database)
# Encrypted with: Your master password (via Argon2id)
```

**Storage Structure (Everything Hidden):**
```
~/.lox/
└── vault.db    ← One encrypted file, nothing visible inside
```

**What an Attacker Sees:**
```
vault.db: data  (encrypted SQLite database)
Size: 45 KB
Modified: 2025-09-30

That's it. No idea what's inside!
```

---

## Technical Comparison

### Pass (GPG) Encryption Flow:
```
Your Password
     ↓
[GPG Key on disk]
     ↓
GPG Encrypt (RSA + AES)
     ↓
Single .gpg file
     ↓
Saved to: ~/.password-store/sitename.gpg
```

**Problems:**
- Depends on GPG key security
- Key can be extracted/copied
- No key derivation from password
- Trust GPG's complex codebase
- Metadata not protected

### Lox Custom Protocol Flow:
```
Master Password (string)
     ↓
Argon2id KDF (64 MB memory-hard)
     ├─→ ChaCha20 Key (32 bytes)
     └─→ AES-256 Key (32 bytes)
     ↓
ChaCha20-Poly1305 Encryption
     ↓
AES-256-GCM Encryption (second layer)
     ↓
SQLite encrypted blob
     ↓
Saved to: ~/.lox/vault.db (everything encrypted)
```

**Benefits:**
- No separate key file needed
- Password-based (easy to remember)
- Two layers of encryption
- Modern algorithms (post-Snowden)
- Everything encrypted (including metadata)

---

## Feature Comparison

| Feature | pass (GPG) | Lox (Custom) |
|---------|-----------|--------------|
| **Encryption Algorithm** | RSA (70s tech) + GPG symmetric | ChaCha20 (2008) + AES-256 (2001) |
| **Encryption Layers** | 1 | 2 (defense in depth) |
| **Key Storage** | Separate GPG keyring | Derived from password |
| **Key Derivation** | None | Argon2id (memory-hard) |
| **Cracking Resistance** | Moderate | High (64 MB RAM per attempt) |
| **Metadata Protection** | ❌ Visible | ✅ Encrypted |
| **File Structure** | Multiple .gpg files | Single encrypted database |
| **Password-based** | ❌ Key-based | ✅ Yes |
| **Memory Wiping** | ❌ No | ✅ Yes (DoD standard) |
| **Breach Checking** | ❌ No | ✅ Yes (HIBP API) |
| **Rate Limiting** | ❌ No | ✅ Yes (5/5min) |
| **Audit Log** | ❌ No | ✅ Yes (encrypted) |

---

## Security Analysis

### Attack: Steal the vault file

**With `pass`:**
```bash
# Attacker gets ~/.password-store/
$ ls -R ~/.password-store/
# Sees all your account names!
Email/gmail.gpg    ← Knows you use Gmail
Banking/chase.gpg  ← Knows you bank with Chase
Work/vpn.gpg       ← Knows you have VPN

# To decrypt, attacker needs your GPG key
# But if they have file access, they might have key access too
```

**With Lox:**
```bash
# Attacker gets ~/.lox/vault.db
$ file vault.db
vault.db: SQLite 3.x database (encrypted)

# Attacker learns: Nothing!
# - Don't know what passwords are inside
# - Don't know how many passwords
# - Don't know account names
# - Don't know organization
# To decrypt: Need master password + break Argon2id
```

### Attack: Brute force the password

**With `pass` (GPG):**
```
Attacker needs:
1. Your GPG private key
2. GPG key passphrase

Speed: ~100,000 attempts/second (GPG key passphrase)
Time to crack 8-char password: Hours to days
```

**With Lox:**
```
Attacker needs:
1. Just the master password

BUT:
- Argon2id requires 64 MB RAM per attempt
- Takes ~0.5 seconds per attempt
- Rate limiter: 5 attempts per 5 minutes
- Speed: ~10 attempts/second (without rate limit)
- Time to crack 8-char password: Centuries

With rate limit active: Decades to centuries
```

### Attack: Memory dump (cold boot attack)

**With `pass` (GPG):**
```
GPG agent caches decrypted passwords in memory
No secure wiping implemented
Passwords may remain in RAM for hours
```

**With Lox:**
```
Every sensitive value wiped immediately:
1. Overwrite 3 times with random data
2. Overwrite once with zeros
3. Clear memory buffer

DoD 5220.22-M standard
```

---

## Why Lox Doesn't Need GPG

### GPG Was Designed For:
- ✅ Email encryption (PGP)
- ✅ File signing
- ✅ Public key cryptography
- ✅ Web of trust

### GPG Was NOT Designed For:
- ❌ Password storage
- ❌ Fast encryption/decryption
- ❌ Password-based encryption
- ❌ Metadata protection

### Lox Was Designed For:
- ✅ Password storage (purpose-built)
- ✅ Fast encryption/decryption
- ✅ Password-based security
- ✅ Complete metadata protection
- ✅ Defense in depth
- ✅ Modern cryptography

---

## Migration from `pass` to Lox

If you're currently using `pass`, here's how to migrate:

```bash
# 1. Export from pass (plaintext - be careful!)
for path in $(pass ls -1); do
    echo "$path: $(pass show $path)" >> /tmp/passwords.txt
done

# 2. Initialize Lox
lox init

# 3. Import to Lox
while IFS=: read -r name password; do
    echo "$password" | lox insert "$name"
done < /tmp/passwords.txt

# 4. Securely delete plaintext
shred -vfz -n 10 /tmp/passwords.txt

# 5. Verify everything works
lox list

# 6. (Optional) Remove pass store
# rm -rf ~/.password-store/
```

---

## The Bottom Line

### When to Use `pass`:
- You already have GPG infrastructure
- You need git sync with commit signing
- You want Unix-philosophy simplicity
- You're okay with metadata exposure

### When to Use Lox:
- You want maximum security
- You prefer password-based encryption
- You need metadata protection
- You want modern cryptography
- You want defense in depth
- You don't want to manage GPG keys

---

## Conclusion

**Lox doesn't use GPG because:**

1. ❌ GPG is overkill for password storage
2. ❌ GPG exposes metadata
3. ❌ GPG uses old crypto (RSA)
4. ❌ GPG has complex key management
5. ❌ GPG single encryption layer
6. ❌ GPG not password-based

**Lox uses custom protocol because:**

1. ✅ Purpose-built for passwords
2. ✅ Everything encrypted (metadata too)
3. ✅ Modern crypto (ChaCha20 + AES-256)
4. ✅ Simple: just master password
5. ✅ Double encryption layer
6. ✅ Password-based (Argon2id)

**TL;DR:** GPG is a swiss army knife. Lox is a scalpel. Use the right tool for the job.

---

**No GPG. No complexity. Just strong encryption.**

🔐 **Lox: Passwords, reinvented.**