# 🔐 Lox Quick Start Guide

Your simple guide to managing passwords with Lox.

---

## 🚀 First Time Setup

### 1. Install Lox

```bash
cd ~/lox
./install.sh
source ~/.zshrc
```

### 2. Initialize Your Vault

```bash
lox init
```

You'll be asked to create a **master password**. This is the ONLY password you need to remember.

**⚠️ IMPORTANT:**
- Choose a strong master password (16+ characters recommended)
- **Write it down** and keep it somewhere safe
- If you lose it, **all passwords are gone forever**
- Use a passphrase like: "MyDog&Coffee!2025-Secure"

---

## 📝 Daily Usage

### Adding Passwords

**Option 1: Add an existing password**
```bash
lox insert github -u your@email.com --url https://github.com
# You'll be prompted to enter the password
```

**Option 2: Generate a secure password**
```bash
lox generate github 32 -u your@email.com --url https://github.com
# Lox creates a strong 32-character password automatically
```

**With tags for organization:**
```bash
lox insert gmail -u you@gmail.com --url https://gmail.com -t personal -t email
lox generate aws-prod 40 -u admin@company.com -t work -t cloud
```

### Viewing Passwords

**List all your passwords:**
```bash
lox list
```

**Show a specific password:**
```bash
lox show github
# Displays password on screen
```

**Copy to clipboard (safer):**
```bash
lox show github --clip
# Copies password to clipboard for 45 seconds
```

### Finding Passwords

**Search by name/username/URL:**
```bash
lox search github
lox search @gmail.com
lox search work
```

**Filter by tag:**
```bash
lox list --tag work
lox list --tag personal
```

### Deleting Passwords

```bash
lox delete old-account
# You'll be asked to confirm
```

---

## 💾 Backups

### Creating Backups

**Make an encrypted backup:**
```bash
# Backup to specific location
lox export ~/Documents/lox-backup-2025-10-05.lox

# Or backup to external drive
lox export /Volumes/USB/lox-backup.lox
```

**⚠️ IMPORTANT:**
- Backup files are encrypted with your master password
- Store backups on USB drives, external hard drives, or secure cloud storage
- Make backups regularly (weekly or monthly)

### Backup Schedule Recommendation

```bash
# Create a backup directory
mkdir -p ~/Documents/lox-backups

# Export with date stamp
lox export ~/Documents/lox-backups/lox-backup-$(date +%Y-%m-%d).lox
```

**Add to your calendar:**
- Every Sunday: Make a new backup
- Every month: Copy backup to external USB drive
- Keep 3-4 recent backups

---

## 🔒 Security Best Practices

### Master Password
✅ **DO:**
- Use 16+ characters
- Use a passphrase with multiple words
- Write it down and store securely (safe, safety deposit box)
- Never share it with anyone

❌ **DON'T:**
- Use dictionary words alone
- Reuse from other services
- Store in plain text files
- Email it to yourself

### Daily Operations
✅ **DO:**
- Use `--clip` to copy passwords (safer than displaying)
- Close terminal after using passwords
- Lock your computer when away
- Check breach warnings when adding passwords

❌ **DON'T:**
- Screenshot passwords
- Send passwords in plain text
- Leave passwords visible on screen
- Share your vault file

### Backups
✅ **DO:**
- Make regular backups (weekly)
- Store on multiple locations (USB + external HD)
- Test backups occasionally (can you open them?)
- Keep backup files encrypted

❌ **DON'T:**
- Store only one backup
- Upload to unencrypted cloud storage
- Forget to make backups
- Delete old backups immediately (keep 2-3)

---

## 📋 Common Workflows

### Workflow 1: Adding a New Account
```bash
# Generate secure password and save
lox generate spotify 32 -u yourname@email.com --url https://spotify.com -t personal -t entertainment

# Copy to clipboard
lox show spotify --clip

# Go sign up on Spotify and paste the password
# Done! Password is securely stored.
```

### Workflow 2: Changing a Password
```bash
# Generate new password
lox generate github 40 --clip

# Paste in GitHub's "change password" form
# Delete old entry (if you gave it a different name)
lox delete github-old
```

### Workflow 3: Daily Access
```bash
# See what you have
lox list

# Copy password you need
lox show gmail --clip

# Paste into login form
# Clipboard auto-clears after 45 seconds
```

### Workflow 4: Weekly Backup
```bash
# Sunday routine
lox export ~/Documents/lox-backups/backup-$(date +%Y-%m-%d).lox

# Check it worked
ls -lh ~/Documents/lox-backups/
```

---

## 🆘 Troubleshooting

### "Vault not initialized"
```bash
# You need to initialize first
lox init
```

### "Invalid master password"
- Check for typos (passwords are case-sensitive)
- After 5 wrong attempts, wait 5 minutes
- If truly forgotten: **passwords cannot be recovered**

### "Command not found: lox"
```bash
# Reload your shell configuration
source ~/.zshrc

# Or run directly
cd ~/lox && source venv/bin/activate && python3 lox.py
```

### Can't copy to clipboard
```bash
# On macOS, should work out of the box
# Just display password instead
lox show github
```

---

## 📚 Quick Reference Card

```
COMMAND                              WHAT IT DOES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
lox init                             Create new vault
lox insert NAME                      Add password manually
lox generate NAME [LENGTH]           Generate secure password
lox show NAME                        Display password
lox show NAME --clip                 Copy password to clipboard
lox list                             Show all passwords
lox list --tag TAGNAME               Filter by tag
lox search QUERY                     Search passwords
lox delete NAME                      Remove password
lox export FILE                      Create backup
lox audit                            View activity log
```

### Common Options
```
-u, --username      Set username/email
--url               Set website URL
-t, --tags          Add tags (use multiple times)
-c, --clip          Copy to clipboard
--no-symbols        Generate without special characters
```

---

## 💡 Tips & Tricks

### Use Tags to Organize
```bash
lox generate facebook 32 -t personal -t social
lox generate slack 32 -t work -t communication
lox generate mysql-prod 40 -t work -t database -t production

# Later, list by category
lox list --tag work
lox list --tag personal
```

### Generate Different Password Lengths
```bash
lox generate pin 4 --no-symbols        # Short numeric-ish PIN
lox generate website 24                # Standard website (24 chars)
lox generate api-key 64                # Long API key (64 chars)
```

### Use Descriptive Names
```bash
✅ GOOD:
lox generate gmail-personal
lox generate gmail-work
lox generate aws-production
lox generate github-personal

❌ AVOID:
lox generate email
lox generate pass1
lox generate temp
```

### Copy-Paste Workflow
```bash
# Generate and copy in one command
lox generate new-service 32 --clip

# Now just paste (Cmd+V) - password already in clipboard
# It will auto-clear after 45 seconds
```

---

## 🎯 Your First 5 Minutes with Lox

```bash
# 1. Initialize
lox init

# 2. Add your most important password
lox insert primary-email -u you@gmail.com --url https://gmail.com

# 3. Generate a secure password for something new
lox generate test-site 32 --clip

# 4. See what you have
lox list

# 5. Make your first backup
lox export ~/lox-backup.lox

# Done! You're now using Lox.
```

---

## 🔄 Restore from Backup (Future Reference)

If you ever need to restore:

```bash
# Your vault file is just the database
# To restore, simply copy your backup over it:
cp ~/Documents/lox-backups/lox-backup-2025-10-05.lox ~/.lox/vault.db

# Or start fresh on a new computer:
lox init    # Create new vault
# Then manually re-enter passwords
# (There's no import feature yet - backups are for vault.db restoration)
```

---

**Remember:** Your master password is the key to everything. Keep it safe! 🔐

**Need more help?** Check `README.md` for advanced features.
