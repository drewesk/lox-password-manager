# 🔐 Lox - Secure Password Manager

**A more secure alternative to `pass` with military-grade encryption and modern security practices.**

Lox is a command-line password manager that goes beyond traditional tools like `pass` by implementing multiple layers of defense-in-depth security measures.

## 🛡️ Security Architecture

### How `pass` Works (and its limitations)

`pass` is a simple, elegant password manager that:
- Uses **GPG** (GNU Privacy Guard) for encryption
- Stores each password in a separate `.gpg` file
- Files are organized in a plaintext directory tree
- Relies on your GPG key for all security

**Security Limitations of `pass`:**
1. **Single-layer encryption** - Only GPG protects your passwords
2. **Metadata leakage** - File/directory names reveal password organization
3. **No key derivation** - Relies solely on GPG key management
4. **Individual file vulnerabilities** - Each file can be targeted separately
5. **No secure memory wiping** - Passwords may remain in RAM
6. **No password breach checking** - Can't detect compromised passwords
7. **No rate limiting** - Vulnerable to brute force attacks

### How Lox Improves Security

Lox implements multiple layers of defense:

#### 1. **Multi-Layer Encryption** 🔒
- **Layer 1: ChaCha20-Poly1305** - Stream cipher with authentication
- **Layer 2: AES-256-GCM** - Block cipher with Galois Counter Mode
- Provides defense-in-depth: if one algorithm is broken, the other protects your data

#### 2. **Argon2id Key Derivation** 🔑
- **Memory-hard** function (64 MB memory cost)
- Resistant to GPU/ASIC cracking attacks
- OWASP recommended parameters (3 iterations, 4 threads)
- Far superior to PBKDF2 or bcrypt

#### 3. **Encrypted Database** 💾
- **No metadata leakage** - Everything is encrypted, including entry names
- Single encrypted SQLite database instead of directory tree
- Atomic operations with transaction support

#### 4. **Secure Memory Management** 🧹
- Automatic memory wiping using DoD 5220.22-M standard
- Overwrites sensitive data 3 times with random data + final zero pass
- Prevents cold boot attacks and memory dumps

#### 5. **Password Breach Checking** 🔍
- Integrates with Have I Been Pwned API
- Uses **k-anonymity** - only first 5 chars of hash sent (privacy-preserving)
- Warns you if passwords appear in known breaches

#### 6. **Rate Limiting** ⏱️
- Prevents brute force attacks on master password
- 5 attempts per 5-minute window
- Automatic lockout with countdown timer

#### 7. **Encrypted Audit Logging** 📊
- All operations are logged with timestamps
- Logs are encrypted with your master password
- Track access patterns and detect unauthorized use

#### 8. **Secure Clipboard Management** 📋
- Auto-clear after 45 seconds
- Restores previous clipboard content
- Thread-safe with cancellation support

#### 9. **Password Strength Analysis** 💪
- Shannon entropy calculation
- Character diversity checking
- Common pattern detection
- Real-time strength scoring (0-100)

## 📦 Installation

### Requirements
- Python 3.8+
- pip

### Install Dependencies

```bash
cd ~/lox
pip install -r requirements.txt
```

### Make Executable

```bash
chmod +x ~/lox/lox.py
```

### Add to PATH (Optional)

Add to your `~/.zshrc`:

```bash
# Lox Password Manager
export PATH="$HOME/lox:$PATH"
alias lox="python3 $HOME/lox/lox.py"
```

Then reload:

```bash
source ~/.zshrc
```

## 🚀 Quick Start

### 1. Initialize Your Vault

```bash
lox init
```

You'll be prompted to create a master password. Choose a strong one - Lox will analyze its strength!

### 2. Add a Password

```bash
# Manually enter a password
lox insert github --username your@email.com --url https://github.com

# Check if it's been breached
# Lox will automatically check against Have I Been Pwned
```

### 3. Generate a Secure Password

```bash
# Generate a 32-character password with symbols
lox generate aws-prod 32

# Generate without symbols (alphanumeric only)
lox generate mysql-db 24 --no-symbols

# Generate and copy to clipboard
lox generate api-key 40 --clip
```

### 4. Retrieve a Password

```bash
# Display password
lox show github

# Copy to clipboard (clears after 45 seconds)
lox show github --clip
```

### 5. List All Passwords

```bash
# List all entries
lox list

# Filter by tag
lox list --tag work
```

## 📖 Complete Command Reference

### `lox init`
Initialize a new password vault.

```bash
lox init [--storage-path PATH]
```

**Options:**
- `--storage-path, -s` - Custom vault location (default: `~/.lox/vault.db`)

---

### `lox insert`
Insert a new password entry.

```bash
lox insert NAME [OPTIONS]
```

**Arguments:**
- `NAME` - Unique name for the password entry

**Options:**
- `--username, -u` - Username or email
- `--url` - Website URL
- `--notes, -n` - Additional notes
- `--tags, -t` - Tags (can specify multiple: `-t work -t prod`)
- `--multiline, -m` - Read multiline password (Ctrl-D to finish)
- `--storage-path, -s` - Custom vault location

**Examples:**
```bash
lox insert gmail -u john@gmail.com --url https://gmail.com
lox insert ssh-server -t servers -t production
lox insert api-key -m  # For multiline secrets
```

---

### `lox generate`
Generate a secure random password.

```bash
lox generate NAME [LENGTH] [OPTIONS]
```

**Arguments:**
- `NAME` - Name for the password entry
- `LENGTH` - Password length (default: 32)

**Options:**
- `--no-symbols, -n` - Generate without symbols (alphanumeric only)
- `--clip, -c` - Copy to clipboard instead of displaying
- `--username, -u` - Username
- `--url` - Website URL
- `--tags, -t` - Tags

**Examples:**
```bash
lox generate facebook 24
lox generate vpn 32 --clip
lox generate wifi 16 --no-symbols
```

---

### `lox show`
Display or copy a password.

```bash
lox show NAME [OPTIONS]
```

**Arguments:**
- `NAME` - Name of the password entry

**Options:**
- `--clip, -c` - Copy to clipboard (clears after 45 seconds)
- `--storage-path, -s` - Custom vault location

**Examples:**
```bash
lox show gmail
lox show github --clip
```

---

### `lox list`
List all password entries.

```bash
lox list [OPTIONS]
```

**Options:**
- `--tag, -t` - Filter by tag
- `--storage-path, -s` - Custom vault location

**Examples:**
```bash
lox list
lox list --tag work
```

---

### `lox search`
Search for passwords.

```bash
lox search QUERY [OPTIONS]
```

**Arguments:**
- `QUERY` - Search term (searches name, username, URL, notes)

**Examples:**
```bash
lox search github
lox search @work.com
```

---

### `lox delete`
Delete a password entry.

```bash
lox delete NAME [OPTIONS]
```

**Arguments:**
- `NAME` - Name of the password entry to delete

**Examples:**
```bash
lox delete old-account
```

---

### `lox audit`
View encrypted audit log.

```bash
lox audit [OPTIONS]
```

**Options:**
- `--limit, -l` - Number of entries to show (default: 50)

**Examples:**
```bash
lox audit
lox audit --limit 100
```

---

### `lox export`
Export vault to encrypted backup file.

```bash
lox export FILENAME [OPTIONS]
```

**Arguments:**
- `FILENAME` - Export file path

**Examples:**
```bash
lox export ~/backup/passwords-2025.lox
```

**⚠️ Warning:** Keep export files secure - they contain all your passwords!

---

## 🔒 Security Best Practices

### Master Password
1. **Use a strong master password** (16+ characters recommended)
2. **Use a passphrase** with multiple words and numbers
3. **Never reuse** your master password elsewhere
4. **Cannot be recovered** - if lost, all passwords are inaccessible

### Operational Security
1. **Regular backups** - Use `lox export` to create encrypted backups
2. **Audit logs** - Regularly check `lox audit` for suspicious activity
3. **Password rotation** - Periodically update important passwords
4. **Breach checking** - Lox automatically checks passwords against known breaches
5. **Clipboard security** - Always use `--clip` on shared/public computers

### Storage
1. **Default location** - `~/.lox/vault.db` with 0600 permissions
2. **Backup location** - Store encrypted exports on separate devices
3. **No cloud sync** - Don't sync vault to cloud without additional encryption
4. **USB backup** - Consider encrypted USB backup for critical passwords

## 🆚 Comparison with `pass`

| Feature | pass | Lox |
|---------|------|-----|
| **Encryption** | GPG only | ChaCha20-Poly1305 + AES-256-GCM |
| **Key Derivation** | GPG key | Argon2id (memory-hard) |
| **Metadata Protection** | ❌ File names visible | ✅ Fully encrypted |
| **Storage Format** | Individual files | Encrypted SQLite database |
| **Memory Security** | ❌ No wiping | ✅ Secure memory wiping |
| **Breach Checking** | ❌ | ✅ Have I Been Pwned integration |
| **Rate Limiting** | ❌ | ✅ Brute force protection |
| **Audit Logging** | ❌ | ✅ Encrypted audit log |
| **Password Strength** | ❌ | ✅ Real-time analysis |
| **Clipboard Security** | Basic | Advanced with auto-clear |

## 🔧 Technical Details

### Encryption Format

Each encrypted entry has this structure:

```
[32 bytes: Argon2 salt]
[12 bytes: ChaCha20 nonce]
[12 bytes: AES-GCM nonce]
[variable: ciphertext with auth tags]
```

### Key Derivation Parameters

```python
Argon2id:
  - Time cost: 3 iterations
  - Memory cost: 64 MB (65536 KB)
  - Parallelism: 4 threads
  - Output: 64 bytes (split into two 32-byte keys)
```

### Cryptographic Libraries

- `cryptography` - ChaCha20-Poly1305, AES-256-GCM
- `argon2-cffi` - Argon2id implementation
- `pynacl` - Additional cryptographic primitives

## 🐛 Troubleshooting

### "Vault not initialized" Error
```bash
# Run init first
lox init
```

### "Invalid master password" Error
- Check your master password carefully (case-sensitive)
- After 5 failed attempts, wait 5 minutes

### Clipboard Not Working
```bash
# Install clipboard dependencies
# On macOS (should work out of box)
# On Linux:
sudo apt-get install xclip  # or xsel
```

### Permission Errors
```bash
# Fix vault permissions
chmod 600 ~/.lox/vault.db
chmod 700 ~/.lox
```

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- Inspired by `pass` (passwordstore.org)
- Built with Python cryptography best practices
- OWASP guidelines for password storage
- Have I Been Pwned API for breach checking

## ⚠️ Disclaimer

While Lox implements strong security measures, no system is perfectly secure. Always:
- Keep your system updated
- Use full disk encryption
- Protect your master password
- Make regular backups

**Use at your own risk. The author is not responsible for any data loss or security breaches.**

---

**Made with 🔐 for secure password management**