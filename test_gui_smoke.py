#!/usr/bin/env python3
"""
Smoke test for Lox GUI components.
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto import MultiLayerEncryption
from storage import EncryptedStorage
from security import PasswordStrengthAnalyzer, PasswordBreachChecker


def test_crypto():
    print("Testing cryptography...")
    crypto = MultiLayerEncryption()

    # Test password generation
    password = crypto.generate_secure_password(16)
    assert len(password) == 16
    print(f"  ✓ Password generation: {password[:8]}...")

    # Test encryption/decryption
    plaintext = b"Secret message"
    master_password = "test-master-password"
    encrypted = crypto.encrypt(plaintext, master_password)
    decrypted = crypto.decrypt(encrypted, master_password)
    assert decrypted == plaintext
    print("  ✓ Encryption/decryption")

    # Test password hashing
    hash_str = crypto.hash_password(master_password)
    assert crypto.verify_password(hash_str, master_password)
    print("  ✓ Password hashing")

    return True


def test_storage():
    print("Testing storage...")

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        storage = EncryptedStorage(db_path)
        master_password = "test-master-password-123"

        # Initialize vault
        storage.initialize(master_password)
        print("  ✓ Vault initialization")

        # Verify master password
        assert storage.verify_master_password(master_password)
        print("  ✓ Master password verification")

        # Insert password
        entry_id = storage.insert_password(
            master_password=master_password,
            name="test-entry",
            password="test-password-456",
            username="test@example.com",
            url="https://example.com",
            tags=["test", "demo"],
        )
        assert entry_id
        print("  ✓ Password insertion")

        # Retrieve password
        entry = storage.get_password(master_password, "test-entry")
        assert entry is not None
        assert entry["name"] == "test-entry"
        assert entry["password"] == "test-password-456"
        print("  ✓ Password retrieval")

        # List passwords
        entries = storage.list_passwords(master_password)
        assert len(entries) == 1
        print("  ✓ List passwords")

        # Search passwords (search for "example" in username)
        results = storage.search_passwords(master_password, "example")
        assert len(results) == 1
        print("  ✓ Search passwords")

        # Export encrypted
        export_path = db_path + ".export"
        storage.export_encrypted(master_password, export_path)
        assert os.path.exists(export_path)
        print("  ✓ Export encrypted")

        # Export with recovery key (new method)
        if hasattr(storage, "export_with_recovery_key"):
            recovery_path = db_path + ".recovery.export"
            recovery_key = storage.export_with_recovery_key(
                master_password, recovery_path
            )
            assert os.path.exists(recovery_path)
            print("  ✓ Export with recovery key")

        # Import encrypted (new method)
        if hasattr(storage, "import_encrypted"):
            # Create a second vault for import test
            storage2 = EncryptedStorage(db_path + ".import.db")
            storage2.initialize(master_password)
            imported = storage2.import_encrypted(master_password, export_path)
            assert imported >= 1
            print(f"  ✓ Import encrypted ({imported} entries)")
            storage2.close()

        # Delete password
        assert storage.delete_password(master_password, "test-entry")
        print("  ✓ Password deletion")

        storage.close()

    finally:
        # Cleanup
        for f in [
            db_path,
            db_path + ".export",
            db_path + ".recovery.export",
            db_path + ".import.db",
        ]:
            if os.path.exists(f):
                os.unlink(f)

    return True


def test_security():
    print("Testing security utilities...")

    analyzer = PasswordStrengthAnalyzer()
    result = analyzer.analyze_strength("StrongPass123!@#")
    assert result["score"] > 50
    print("  ✓ Password strength analysis")

    # Note: breach checker requires network, skip for smoke test
    print("  ⚠️  Breach checker (network test skipped)")

    return True


def main():
    print("Running Lox smoke tests...")
    print("=" * 60)

    try:
        test_crypto()
        print()
        test_storage()
        print()
        test_security()
        print()
        print("=" * 60)
        print("All smoke tests passed! ✅")
        return 0
    except Exception as e:
        print()
        print("=" * 60)
        print(f"Test failed: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
