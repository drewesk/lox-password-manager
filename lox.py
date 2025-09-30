#!/usr/bin/env python3
"""
Lox - Secure Password Manager
A more secure alternative to pass with multi-layer encryption
"""

import sys
import os
import getpass
import click
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init
import random

from crypto import MultiLayerEncryption
from storage import EncryptedStorage
from security import (
    SecureClipboard,
    PasswordBreachChecker,
    PasswordStrengthAnalyzer,
    RateLimiter
)

# Initialize colorama
init(autoreset=True)

# Version
VERSION = "1.0.0"

# Global rate limiter
rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)

# ASCII Art
LOX_LOGO = r"""
    ██╗      ██████╗ ██╗  ██╗
    ██║     ██╔═══██╗╚██╗██╔╝
    ██║     ██║   ██║ ╚███╔╝ 
    ██║     ██║   ██║ ██╔██╗ 
    ███████╗╚██████╔╝██╔╝ ██╗
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
    🔐 Secure Password Manager
"""

LOCK_ICONS = ['🔐', '🔒', '🔓', '🗝️', '🛡️', '⚡', '✨', '🌟']
SUCCESS_ICONS = ['✓', '✔', '✅', '🎉', '🎊', '⭐', '💎', '🏆']
WARNING_ICONS = ['⚠', '⚡', '💥', '🔥', '🚨']
ERROR_ICONS = ['✗', '✘', '❌', '🚫', '💀']


def print_success(message: str, icon: str = None):
    """Print success message in green"""
    if icon is None:
        icon = random.choice(SUCCESS_ICONS)
    click.echo(f"{Fore.GREEN}{icon} {message}{Style.RESET_ALL}")


def print_error(message: str, icon: str = None):
    """Print error message in red"""
    if icon is None:
        icon = random.choice(ERROR_ICONS)
    click.echo(f"{Fore.RED}{icon} {message}{Style.RESET_ALL}", err=True)


def print_warning(message: str, icon: str = None):
    """Print warning message in yellow"""
    if icon is None:
        icon = random.choice(WARNING_ICONS)
    click.echo(f"{Fore.YELLOW}{icon} {message}{Style.RESET_ALL}")


def print_info(message: str, icon: str = '💡'):
    """Print info message in blue"""
    click.echo(f"{Fore.CYAN}{icon} {message}{Style.RESET_ALL}")


def print_logo():
    """Print the Lox logo with colors"""
    colors = [Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    for i, line in enumerate(LOX_LOGO.split('\n')):
        color = colors[i % len(colors)]
        click.echo(f"{color}{line}{Style.RESET_ALL}")


def print_box(message: str, color=Fore.CYAN, padding=2):
    """Print a message in a box"""
    lines = message.split('\n')
    max_len = max(len(line) for line in lines)
    
    border = '═' * (max_len + padding * 2)
    click.echo(f"{color}╔{border}╗{Style.RESET_ALL}")
    
    for line in lines:
        padded_line = line.ljust(max_len)
        click.echo(f"{color}║{' ' * padding}{padded_line}{' ' * padding}║{Style.RESET_ALL}")
    
    click.echo(f"{color}╚{border}╝{Style.RESET_ALL}")


def animate_text(text: str, delay: float = 0.02):
    """Animate text appearing character by character"""
    import time
    for char in text:
        click.echo(char, nl=False)
        time.sleep(delay)
    click.echo()  # New line at the end


def print_password_strength_bar(score: int):
    """Print a visual password strength bar"""
    bar_length = 20
    filled = int((score / 100) * bar_length)
    
    if score < 30:
        color = Fore.RED
        label = "Weak"
    elif score < 60:
        color = Fore.YELLOW
        label = "Fair"
    elif score < 80:
        color = Fore.CYAN
        label = "Good"
    else:
        color = Fore.GREEN
        label = "Strong"
    
    bar = '█' * filled + '░' * (bar_length - filled)
    click.echo(f"{color}{bar} {score}% - {label}{Style.RESET_ALL}")


def get_master_password(storage: EncryptedStorage, confirm: bool = False) -> str:
    """Get master password from user with rate limiting"""
    if rate_limiter.is_limited():
        time_left = rate_limiter.time_until_reset()
        print_error(f"Too many failed attempts. Please wait {time_left} seconds.")
        sys.exit(1)
    
    password = getpass.getpass(f"{Fore.CYAN}Master password: {Style.RESET_ALL}")
    
    if confirm:
        password2 = getpass.getpass(f"{Fore.CYAN}Confirm master password: {Style.RESET_ALL}")
        if password != password2:
            print_error("Passwords do not match")
            sys.exit(1)
    else:
        # Verify password if not confirming (i.e., for existing vault)
        if not storage.verify_master_password(password):
            rate_limiter.record_attempt()
            print_error("Invalid master password")
            sys.exit(1)
    
    return password


@click.group(invoke_without_command=True)
@click.version_option(version=VERSION, prog_name="lox")
@click.pass_context
def cli(ctx):
    """
    🔐 Lox - Secure Password Manager
    
    A more secure alternative to pass with multi-layer encryption,
    Argon2id key derivation, and metadata protection.
    """
    if ctx.invoked_subcommand is None:
        print_logo()
        click.echo()
        click.echo(f"{Fore.CYAN}Version:{Style.RESET_ALL} {VERSION}")
        click.echo(f"{Fore.CYAN}Commands:{Style.RESET_ALL} Run 'lox --help' for available commands")
        click.echo()


@cli.command()
@click.option('--storage-path', '-s', help='Custom storage location')
def init(storage_path):
    """Initialize a new password vault"""
    print_logo()
    click.echo()
    
    storage = EncryptedStorage(storage_path)
    
    # Check if already initialized
    if storage.storage_path.exists():
        print_error(f"Vault already exists at {storage.storage_path}")
        if not click.confirm("Do you want to reinitialize (THIS WILL DELETE ALL PASSWORDS)?"):
            sys.exit(0)
        storage.storage_path.unlink()
    
    print_box("🔐 VAULT INITIALIZATION\n\nYou're about to create a secure password vault.\nChoose a strong master password.", Fore.CYAN)
    click.echo()
    print_warning("⚠️  Your master password cannot be recovered if lost!")
    click.echo()
    
    # Get master password
    master_password = getpass.getpass(f"{Fore.CYAN}Master password: {Style.RESET_ALL}")
    master_password2 = getpass.getpass(f"{Fore.CYAN}Confirm master password: {Style.RESET_ALL}")
    
    if master_password != master_password2:
        print_error("Passwords do not match")
        sys.exit(1)
    
    # Analyze password strength
    click.echo()
    print_info("🔍 Analyzing password strength...", icon='🔍')
    analyzer = PasswordStrengthAnalyzer()
    strength = analyzer.analyze_strength(master_password)
    
    click.echo()
    click.echo(f"{Fore.CYAN}Password Strength Analysis:{Style.RESET_ALL}")
    print_password_strength_bar(strength['score'])
    
    if strength['score'] < 60:
        click.echo()
        print_warning(f"Security Note: {strength['strength']} password")
        for feedback in strength['feedback']:
            click.echo(f"  {Fore.YELLOW}→{Style.RESET_ALL} {feedback}")
        
        click.echo()
        if not click.confirm("Continue with this password?"):
            sys.exit(0)
    else:
        click.echo()
        print_success(f"Excellent! Your password is {strength['strength']}")
    
    # Initialize storage
    click.echo()
    print_info("🔨 Creating encrypted vault...", icon='🔨')
    try:
        storage.initialize(master_password)
        click.echo()
        print_success(f"Vault initialized at {storage.storage_path}", icon='🎉')
        click.echo()
        print_box(
            "🛡️  SECURITY FEATURES ENABLED\n\n"
            "✓ Argon2id Key Derivation (64 MB)\n"
            "✓ ChaCha20-Poly1305 Encryption\n"
            "✓ AES-256-GCM Encryption\n"
            "✓ Secure Memory Wiping\n"
            "✓ Encrypted Audit Logging",
            Fore.GREEN
        )
        click.echo()
        print_info("💡 Next steps: lox insert <name> or lox generate <name>")
    except Exception as e:
        print_error(f"Failed to initialize vault: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command()
@click.argument('name')
@click.option('--username', '-u', help='Username/email')
@click.option('--url', help='Website URL')
@click.option('--notes', '-n', help='Additional notes')
@click.option('--tags', '-t', multiple=True, help='Tags (can specify multiple)')
@click.option('--multiline', '-m', is_flag=True, help='Read multiline password')
@click.option('--storage-path', '-s', help='Custom storage location')
def insert(name, username, url, notes, tags, multiline, storage_path):
    """Insert a new password"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        # Get password
        if multiline:
            print_info("Enter password (Ctrl-D or Ctrl-Z to finish):")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass
            password = '\n'.join(lines)
        else:
            password = getpass.getpass(f"{Fore.CYAN}Password for {name}: {Style.RESET_ALL}")
        
        if not password:
            print_error("Password cannot be empty")
            sys.exit(1)
        
        # Check if password is breached
        print_info("Checking if password has been breached...")
        breach_checker = PasswordBreachChecker()
        breach_count = breach_checker.check_breach(password)
        
        if breach_count is not None and breach_count > 0:
            click.echo()
            print_box(
                f"🚨 SECURITY WARNING\n\n"
                f"This password has been seen in {breach_count:,} data breaches!\n"
                f"Using this password is NOT recommended.",
                Fore.RED
            )
            if not click.confirm("\nDo you still want to use this password?"):
                sys.exit(0)
        elif breach_count == 0:
            print_success("Password not found in known breaches", icon='🛡️')
        
        # Insert password
        storage.insert_password(
            master_password=master_password,
            name=name,
            password=password,
            username=username,
            url=url,
            notes=notes,
            tags=list(tags)
        )
        
        click.echo()
        print_success(f"Password '{name}' added to vault", icon='🔐')
        print_info(f"💡 Retrieve with: lox show {name} --clip")
        
    except Exception as e:
        print_error(f"Failed to insert password: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command()
@click.argument('name')
@click.option('--clip', '-c', is_flag=True, help='Copy to clipboard instead of displaying')
@click.option('--storage-path', '-s', help='Custom storage location')
def show(name, clip, storage_path):
    """Show a password"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        entry = storage.get_password(master_password, name)
        
        if not entry:
            print_error(f"Password '{name}' not found")
            sys.exit(1)
        
        if clip:
            # Copy to clipboard
            clipboard = SecureClipboard(timeout=45)
            clipboard.copy(entry['password'])
            click.echo()
            print_success(f"Password copied to clipboard!", icon='📋')
            print_warning(f"⏱️  Will auto-clear in 45 seconds")
        else:
            # Display entry in a beautiful box
            click.echo()
            content = f"🔑 {entry['name']}\n\n"
            
            if entry.get('username'):
                content += f"👤 Username: {entry['username']}\n"
            if entry.get('url'):
                content += f"🌐 URL: {entry['url']}\n"
            content += f"🔐 Password: {entry['password']}\n"
            if entry.get('notes'):
                content += f"📝 Notes: {entry['notes']}\n"
            if entry.get('tags'):
                content += f"🏷️  Tags: {', '.join(entry['tags'])}"
            
            print_box(content, Fore.CYAN)
            click.echo()
    
    except Exception as e:
        print_error(f"Failed to retrieve password: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command()
@click.argument('name')
@click.argument('length', type=int, default=32)
@click.option('--no-symbols', '-n', is_flag=True, help='Generate without symbols')
@click.option('--clip', '-c', is_flag=True, help='Copy to clipboard')
@click.option('--username', '-u', help='Username/email')
@click.option('--url', help='Website URL')
@click.option('--tags', '-t', multiple=True, help='Tags')
@click.option('--storage-path', '-s', help='Custom storage location')
def generate(name, length, no_symbols, clip, username, url, tags, storage_path):
    """Generate a new password"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        # Generate password
        crypto = MultiLayerEncryption()
        password = crypto.generate_secure_password(
            length=length,
            include_symbols=not no_symbols
        )
        
        # Store password
        storage.insert_password(
            master_password=master_password,
            name=name,
            password=password,
            username=username,
            url=url,
            tags=list(tags)
        )
        
        if clip:
            clipboard = SecureClipboard(timeout=45)
            clipboard.copy(password)
            click.echo()
            print_success(f"Generated password for '{name}'!", icon='⚡')
            print_success(f"Copied to clipboard (clears in 45s)", icon='📋')
        else:
            click.echo()
            print_box(
                f"⚡ GENERATED PASSWORD\n\n"
                f"Name: {name}\n"
                f"Length: {length} characters\n\n"
                f"{password}",
                Fore.GREEN
            )
            click.echo()
    
    except Exception as e:
        print_error(f"Failed to generate password: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command(name='list')
@click.option('--tag', '-t', help='Filter by tag')
@click.option('--storage-path', '-s', help='Custom storage location')
def list_passwords(tag, storage_path):
    """List all passwords"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        entries = storage.list_passwords(master_password, tag=tag)
        
        if not entries:
            click.echo()
            print_box("📭 EMPTY VAULT\n\nNo passwords stored yet.\n\nTry: lox generate <name>", Fore.YELLOW)
            return
        
        click.echo()
        header = "🔐 PASSWORD VAULT"
        if tag:
            header += f" (Tag: {tag})"
        print_box(header, Fore.CYAN)
        click.echo()
        
        for i, entry in enumerate(entries, 1):
            icon = random.choice(['🔑', '🗝️', '🔐', '🔓'])
            click.echo(f"{Fore.CYAN}{i}.{Style.RESET_ALL} {icon} {Fore.GREEN}{entry['name']}{Style.RESET_ALL}")
            
            if entry.get('username'):
                click.echo(f"   👤 {entry['username']}")
            if entry.get('url'):
                click.echo(f"   🌐 {entry['url']}")
            if entry.get('tags'):
                tags_str = ' '.join([f"#{tag}" for tag in entry['tags']])
                click.echo(f"   🏷️  {Fore.YELLOW}{tags_str}{Style.RESET_ALL}")
            
            # Format timestamps
            created = datetime.fromtimestamp(entry['created_at']).strftime('%Y-%m-%d %H:%M')
            accessed = datetime.fromtimestamp(entry['accessed_at']).strftime('%Y-%m-%d %H:%M')
            
            click.echo(f"   📅 Created: {created} | 👁️  Last access: {accessed}")
            click.echo()
        
        click.echo(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        click.echo(f"{Fore.GREEN}Total: {len(entries)} password(s){Style.RESET_ALL}\n")
    
    except Exception as e:
        print_error(f"Failed to list passwords: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command()
@click.argument('name')
@click.option('--storage-path', '-s', help='Custom storage location')
@click.confirmation_option(prompt='Are you sure you want to delete this password?')
def delete(name, storage_path):
    """Delete a password"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        if storage.delete_password(master_password, name):
            click.echo()
            print_success(f"Password '{name}' deleted", icon='🗑️')
        else:
            print_error(f"Password '{name}' not found")
            sys.exit(1)
    
    except Exception as e:
        print_error(f"Failed to delete password: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command()
@click.argument('query')
@click.option('--storage-path', '-s', help='Custom storage location')
def search(query, storage_path):
    """Search for passwords"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        results = storage.search_passwords(master_password, query)
        
        if not results:
            print_info(f"No passwords found matching '{query}'")
            return
        
        click.echo(f"\n{Fore.CYAN}Search results for: '{query}'{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        for result in results:
            click.echo(f"{Fore.GREEN}▸ {result['name']}{Style.RESET_ALL}")
            if result.get('username'):
                click.echo(f"  Username: {result['username']}")
            if result.get('url'):
                click.echo(f"  URL: {result['url']}")
            click.echo()
        
        click.echo(f"{Fore.CYAN}Found: {len(results)} match(es){Style.RESET_ALL}\n")
    
    except Exception as e:
        print_error(f"Failed to search: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command()
@click.option('--limit', '-l', default=50, help='Number of entries to show')
@click.option('--storage-path', '-s', help='Custom storage location')
def audit(limit, storage_path):
    """Show audit log"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        logs = storage.get_audit_log(master_password, limit=limit)
        
        if not logs:
            print_info("No audit log entries")
            return
        
        click.echo(f"\n{Fore.CYAN}Audit Log{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        for log in logs:
            timestamp = datetime.fromtimestamp(log['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            click.echo(f"{Fore.YELLOW}[{timestamp}]{Style.RESET_ALL} {log['action']}")
        
        click.echo()
    
    except Exception as e:
        print_error(f"Failed to retrieve audit log: {e}")
        sys.exit(1)
    finally:
        storage.close()


@cli.command()
@click.argument('export_file')
@click.option('--storage-path', '-s', help='Custom storage location')
def export(export_file, storage_path):
    """Export vault to encrypted file"""
    storage = EncryptedStorage(storage_path)
    
    if not storage.storage_path.exists():
        print_error("Vault not initialized. Run 'lox init' first")
        sys.exit(1)
    
    try:
        master_password = get_master_password(storage)
        
        storage.export_encrypted(master_password, export_file)
        print_success(f"Vault exported to {export_file}")
        print_warning("Keep this file secure - it contains all your passwords!")
    
    except Exception as e:
        print_error(f"Failed to export: {e}")
        sys.exit(1)
    finally:
        storage.close()


if __name__ == '__main__':
    cli()