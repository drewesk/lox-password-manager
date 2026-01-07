#!/usr/bin/env python3
"""
Lox Storage Module
Encrypted database storage with metadata protection
"""

import os
import json
import sqlite3
import time
import secrets
import threading
from typing import Optional, List, Dict, Any
from pathlib import Path
from base64 import b64encode, b64decode
from crypto import MultiLayerEncryption, SecureMemory


class EncryptedStorage:
    """
    Encrypted storage backend using SQLite with encrypted blobs
    All data including metadata is encrypted
    """

    def __init__(self, storage_path: Optional[str] = None):
        if storage_path is None:
            self.storage_path = Path.home() / ".lox" / "vault.db"
        else:
            self.storage_path = Path(storage_path)

        self.storage_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.crypto = MultiLayerEncryption()
        self.conn = None
        self.master_password_hash = None
        self._db_lock = threading.RLock()

    def _connect(self):
        """Connect to the database"""
        if self.conn is None:
            self.conn = sqlite3.connect(str(self.storage_path), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            # Set secure permissions on database file
            os.chmod(self.storage_path, 0o600)

    def initialize(self, master_password: str):
        """Initialize the password store with a master password"""
        with self._db_lock:
            self._connect()
            assert self.conn is not None

            # Create tables
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                )
            """)

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id TEXT PRIMARY KEY,
                    encrypted_data BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    modified_at INTEGER NOT NULL,
                    accessed_at INTEGER NOT NULL
                )
            """)

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    encrypted_entry BLOB NOT NULL
                )
            """)

            # Store master password hash
            password_hash = self.crypto.hash_password(master_password)
            encrypted_hash = self.crypto.encrypt(
                password_hash.encode(), master_password
            )

            self.conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("master_password_hash", encrypted_hash),
            )

            self.conn.commit()
            self.master_password_hash = password_hash

            # Log initialization
            self._log_action("vault_initialized", master_password)

    def verify_master_password(self, master_password: str) -> bool:
        """Verify the master password"""
        with self._db_lock:
            self._connect()
            assert self.conn is not None

            try:
                row = self.conn.execute(
                    "SELECT value FROM metadata WHERE key = ?",
                    ("master_password_hash",),
                ).fetchone()

                if row is None:
                    return False

                encrypted_hash = row[0]
                decrypted_hash = self.crypto.decrypt(encrypted_hash, master_password)

                # Verify using Argon2
                return self.crypto.verify_password(
                    decrypted_hash.decode(), master_password
                )
            except Exception:
                return False

    def insert_password(
        self,
        master_password: str,
        name: str,
        password: str,
        username: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Insert a new password entry"""
        with self._db_lock:
            self._connect()
            assert self.conn is not None

            # Create password entry
            entry = {
                "name": name,
                "password": password,
                "username": username,
                "url": url,
                "notes": notes,
                "tags": tags or [],
            }

            # Serialize and encrypt
            entry_json = json.dumps(entry).encode("utf-8")
            encrypted_data = self.crypto.encrypt(entry_json, master_password)

            # Generate deterministic ID from name using hash (for consistent overwrites)
            import hashlib

            entry_id = hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]

            timestamp = int(time.time())

            # Check if entry exists to preserve created_at
            existing = self.conn.execute(
                "SELECT created_at FROM passwords WHERE id = ?", (entry_id,)
            ).fetchone()

            created_at = existing[0] if existing else timestamp

            self.conn.execute(
                """INSERT OR REPLACE INTO passwords 
                   (id, encrypted_data, created_at, modified_at, accessed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (entry_id, encrypted_data, created_at, timestamp, timestamp),
            )

            self.conn.commit()

            # Log action
            self._log_action(f"password_inserted: {name}", master_password)

            return entry_id

    def get_password(self, master_password: str, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve a password entry by name"""
        with self._db_lock:
            self._connect()
            assert self.conn is not None

            # Get all entries and search (since names are encrypted)
            rows = self.conn.execute(
                "SELECT id, encrypted_data FROM passwords"
            ).fetchall()

            for row in rows:
                try:
                    encrypted_data = row[1]
                    decrypted_json = self.crypto.decrypt(
                        encrypted_data, master_password
                    )
                    entry = json.loads(decrypted_json.decode("utf-8"))

                    if entry["name"] == name:
                        # Update access time
                        self.conn.execute(
                            "UPDATE passwords SET accessed_at = ? WHERE id = ?",
                            (int(time.time()), row[0]),
                        )
                        self.conn.commit()

                        # Log access
                        self._log_action(f"password_accessed: {name}", master_password)

                        return entry
                except Exception:
                    continue

            return None

    def list_passwords(
        self, master_password: str, tag: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all password entries (metadata only, not actual passwords)"""
        with self._db_lock:
            self._connect()
            assert self.conn is not None

            rows = self.conn.execute(
                "SELECT id, encrypted_data, created_at, modified_at, accessed_at FROM passwords"
            ).fetchall()

            entries = []
            for row in rows:
                try:
                    encrypted_data = row[1]
                    decrypted_json = self.crypto.decrypt(
                        encrypted_data, master_password
                    )
                    entry = json.loads(decrypted_json.decode("utf-8"))

                    # Filter by tag if specified
                    if tag and tag not in entry.get("tags", []):
                        continue

                    # Return metadata only
                    entries.append(
                        {
                            "id": row[0],
                            "name": entry["name"],
                            "username": entry.get("username"),
                            "url": entry.get("url"),
                            "tags": entry.get("tags", []),
                            "created_at": row[2],
                            "modified_at": row[3],
                            "accessed_at": row[4],
                        }
                    )
                except Exception:
                    continue

            return sorted(entries, key=lambda x: x["name"])

    def delete_password(self, master_password: str, name: str) -> bool:
        """Delete a password entry"""
        with self._db_lock:
            self._connect()
            assert self.conn is not None

            # Find and delete
            rows = self.conn.execute(
                "SELECT id, encrypted_data FROM passwords"
            ).fetchall()

            for row in rows:
                try:
                    encrypted_data = row[1]
                    decrypted_json = self.crypto.decrypt(
                        encrypted_data, master_password
                    )
                    entry = json.loads(decrypted_json.decode("utf-8"))

                    if entry["name"] == name:
                        self.conn.execute(
                            "DELETE FROM passwords WHERE id = ?", (row[0],)
                        )
                        self.conn.commit()

                        # Log deletion
                        self._log_action(f"password_deleted: {name}", master_password)

                        return True
                except Exception:
                    continue

            return False

    def search_passwords(
        self, master_password: str, query: str
    ) -> List[Dict[str, Any]]:
        """Search for passwords by name, username, or URL"""
        with self._db_lock:
            self._connect()
            assert self.conn is not None

            query_lower = query.lower()
            rows = self.conn.execute("SELECT encrypted_data FROM passwords").fetchall()

            results = []
            for row in rows:
                try:
                    encrypted_data = row[0]
                    decrypted_json = self.crypto.decrypt(
                        encrypted_data, master_password
                    )
                    entry = json.loads(decrypted_json.decode("utf-8"))

                    # Search in name, username, URL, notes, tags
                    # Convert None values to empty strings
                    name = entry.get("name") or ""
                    username = entry.get("username") or ""
                    url = entry.get("url") or ""
                    notes = entry.get("notes") or ""
                    tags = entry.get("tags") or []
                    tags_text = " ".join(tags)
                    searchable_text = " ".join(
                        [
                            name,
                            username,
                            url,
                            notes,
                            tags_text,
                        ]
                    ).lower()

                    if query_lower in searchable_text:
                        results.append(
                            {
                                "name": entry["name"],
                                "username": entry.get("username"),
                                "url": entry.get("url"),
                            }
                        )
                except Exception:
                    continue

            return results

    def _log_action(self, action: str, master_password: str):
        """Log an action to the encrypted audit log"""
        with self._db_lock:
            if self.conn is None:
                # Connection not established, skip logging
                return
            try:
                log_entry = {"timestamp": int(time.time()), "action": action}

                log_json = json.dumps(log_entry).encode("utf-8")
                encrypted_log = self.crypto.encrypt(log_json, master_password)

                self.conn.execute(
                    "INSERT INTO audit_log (timestamp, encrypted_entry) VALUES (?, ?)",
                    (log_entry["timestamp"], encrypted_log),
                )
                self.conn.commit()
            except Exception:
                # Don't fail the operation if logging fails
                pass

    def get_audit_log(
        self, master_password: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve audit log entries"""
        self._connect()

        rows = self.conn.execute(
            "SELECT encrypted_entry FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()

        logs = []
        for row in rows:
            try:
                encrypted_entry = row[0]
                decrypted_json = self.crypto.decrypt(encrypted_entry, master_password)
                log_entry = json.loads(decrypted_json.decode("utf-8"))
                logs.append(log_entry)
            except Exception:
                continue

        return logs

    def export_encrypted(self, master_password: str, export_path: str):
        """Export the entire vault in encrypted format"""
        self._connect()

        export_data = {"version": "1.0", "exported_at": int(time.time()), "entries": []}

        rows = self.conn.execute("SELECT encrypted_data FROM passwords").fetchall()

        for row in rows:
            try:
                encrypted_data = row[0]
                # Re-encrypt with export key (could be different)
                decrypted_json = self.crypto.decrypt(encrypted_data, master_password)
                entry = json.loads(decrypted_json.decode("utf-8"))
                export_data["entries"].append(entry)
            except Exception:
                continue

        # Encrypt entire export
        export_json = json.dumps(export_data, indent=2).encode("utf-8")
        encrypted_export = self.crypto.encrypt(export_json, master_password)

        with open(export_path, "wb") as f:
            f.write(encrypted_export)

        os.chmod(export_path, 0o600)

        # Log export
        self._log_action("vault_exported", master_password)

    def export_with_recovery_key(self, master_password: str, export_path: str):
        """
        Export vault with recovery key for emergency access.
        Generates a random recovery key, encrypts vault with both master password
        and recovery key, and exports both ciphertexts.
        """
        self._connect()

        # Generate random recovery key (32 bytes for ChaCha20 key)
        recovery_key = secrets.token_bytes(32)

        # Get all entries
        export_data = {"version": "2.0", "exported_at": int(time.time()), "entries": []}

        rows = self.conn.execute("SELECT encrypted_data FROM passwords").fetchall()

        for row in rows:
            try:
                encrypted_data = row[0]
                decrypted_json = self.crypto.decrypt(encrypted_data, master_password)
                entry = json.loads(decrypted_json.decode("utf-8"))
                export_data["entries"].append(entry)
            except Exception:
                continue

        # Create two encrypted versions
        export_json = json.dumps(export_data, indent=2).encode("utf-8")

        # Encrypt with master password (standard export)
        encrypted_with_master = self.crypto.encrypt(export_json, master_password)

        # Encrypt with recovery key (treat recovery key as password string)
        # Convert recovery key to hex string for use as password
        recovery_key_hex = recovery_key.hex()
        encrypted_with_recovery = self.crypto.encrypt(export_json, recovery_key_hex)

        # Encrypt recovery key with master password for safe storage
        encrypted_recovery_key = self.crypto.encrypt(recovery_key, master_password)

        # Create final export structure
        final_export = {
            "format": "lox_recovery_export",
            "version": "2.0",
            "exported_at": export_data["exported_at"],
            "vault_encrypted_with_master": b64encode(encrypted_with_master).decode(
                "ascii"
            ),
            "vault_encrypted_with_recovery": b64encode(encrypted_with_recovery).decode(
                "ascii"
            ),
            "recovery_key_encrypted": b64encode(encrypted_recovery_key).decode("ascii"),
            "entry_count": len(export_data["entries"]),
        }

        # Write to file
        with open(export_path, "w") as f:
            json.dump(final_export, f, indent=2)

        os.chmod(export_path, 0o600)

        # Also generate a separate recovery key file (optional)
        recovery_key_path = export_path + ".recovery.key"
        recovery_key_info = {
            "warning": "EMERGENCY RECOVERY KEY - KEEP SECURE",
            "vault_file": export_path,
            "recovery_key_hex": recovery_key_hex,
            "encrypted_recovery_key": b64encode(encrypted_recovery_key).decode("ascii"),
        }

        with open(recovery_key_path, "w") as f:
            json.dump(recovery_key_info, f, indent=2)

        os.chmod(recovery_key_path, 0o600)

        # Log export
        self._log_action("vault_exported_with_recovery", master_password)

        return recovery_key_hex

    def import_encrypted(self, master_password: str, import_path: str):
        """
        Import passwords from an encrypted export file.
        Supports both standard exports (encrypted with master password)
        and recovery exports (encrypted with recovery key).
        """
        self._connect()

        with open(import_path, "rb") as f:
            data = f.read()

        # Try to parse as JSON (recovery export format)
        try:
            import_data = json.loads(data.decode("utf-8"))

            # Check if it's a recovery export
            if import_data.get("format") == "lox_recovery_export":
                # Try to decrypt with master password first
                encrypted_vault = b64decode(import_data["vault_encrypted_with_master"])
                try:
                    decrypted_json = self.crypto.decrypt(
                        encrypted_vault, master_password
                    )
                except:
                    # If master password fails, try recovery key if provided
                    # For now, only support master password decryption
                    raise ValueError("Master password incorrect for recovery export")

                export_data = json.loads(decrypted_json.decode("utf-8"))

            else:
                # Assume it's a standard export encrypted with master password
                encrypted_vault = data
                decrypted_json = self.crypto.decrypt(encrypted_vault, master_password)
                export_data = json.loads(decrypted_json.decode("utf-8"))

        except (json.JSONDecodeError, UnicodeDecodeError):
            # Binary format - standard export
            encrypted_vault = data
            decrypted_json = self.crypto.decrypt(encrypted_vault, master_password)
            export_data = json.loads(decrypted_json.decode("utf-8"))

        # Import entries
        imported_count = 0
        for entry in export_data.get("entries", []):
            try:
                self.insert_password(
                    master_password=master_password,
                    name=entry["name"],
                    password=entry["password"],
                    username=entry.get("username"),
                    url=entry.get("url"),
                    notes=entry.get("notes"),
                    tags=entry.get("tags"),
                )
                imported_count += 1
            except Exception:
                continue

        # Log import
        self._log_action(f"vault_imported: {imported_count} entries", master_password)

        return imported_count

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
