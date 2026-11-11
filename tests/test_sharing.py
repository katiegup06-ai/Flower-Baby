"""Bonus A acceptance tests, using disposable keys and invented credentials."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import vault


KEY_PASSPHRASE = "test-only private key passphrase"
MASTER = "test-only long master passphrase"
SITE = "bonus-example-site"
ENTRY = {"username": "bonus-example-user", "password": "fictional-shared-secret-123!"}


class SharingAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.key_directory.cleanup)
        directory = Path(cls.key_directory.name)
        cls.private = directory / "recipient-private.pem"
        cls.public = directory / "recipient-public.pem"
        cls.other_private = directory / "other-private.pem"
        cls.other_public = directory / "other-public.pem"
        vault.generate_sharing_keys(cls.private, cls.public, KEY_PASSPHRASE)
        vault.generate_sharing_keys(cls.other_private, cls.other_public, KEY_PASSPHRASE)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.shared = self.directory / "entry.share.json"

    def share(self, entry=None):
        vault.share_entry(SITE, ENTRY if entry is None else entry, self.public, self.shared)

    def cli(self, *args, secrets=(), vault_path=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        # Explicitly missing vault proves that keygen/open-share are independent.
        path = self.directory / "nonexistent-vault.json" if vault_path is None else vault_path
        with patch("vault.getpass.getpass", side_effect=secrets):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = vault.main(["--vault", str(path), *args])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_keypair_has_encrypted_private_key_and_matching_rsa_public_key(self):
        private_pem = self.private.read_bytes()
        self.assertTrue(private_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertNotIn(KEY_PASSPHRASE.encode(), private_pem)
        with self.assertRaises(TypeError):
            serialization.load_pem_private_key(private_pem, password=None)
        private_key = serialization.load_pem_private_key(
            private_pem, password=KEY_PASSPHRASE.encode(),
        )
        public_key = serialization.load_pem_public_key(self.public.read_bytes())
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)
        self.assertEqual(public_key.key_size, 3072)
        self.assertEqual(public_key.public_numbers().e, 65537)
        self.assertEqual(private_key.public_key().public_numbers(), public_key.public_numbers())

    def test_correct_recipient_can_open_shared_entry(self):
        self.share()
        site, entry = vault.open_shared_entry(self.shared, self.private, KEY_PASSPHRASE)
        self.assertEqual(site, SITE)
        self.assertEqual(entry, ENTRY)

    def test_share_does_not_contain_plaintext_credentials_or_passphrase(self):
        self.share()
        raw = self.shared.read_bytes()
        for value in (SITE, *ENTRY.values(), KEY_PASSPHRASE):
            self.assertNotIn(value.encode(), raw)
        document = json.loads(raw)
        self.assertEqual(document["header"]["format"], "password-manager-share")
        self.assertEqual(document["header"]["version"], 1)
        self.assertEqual(document["header"]["algorithm"], "RSA-OAEP-SHA256+AES-256-GCM")

    def test_entry_larger_than_rsa_payload_limit_round_trips(self):
        # RSA wraps only an AES key; the entry itself can exceed OAEP's size limit.
        long_entry = {"username": "long-entry-user", "password": "Example!" * 1000}
        self.share(long_entry)
        self.assertEqual(
            vault.open_shared_entry(self.shared, self.private, KEY_PASSPHRASE),
            (SITE, long_entry),
        )

    def test_wrong_recipient_private_key_is_rejected(self):
        self.share()
        with self.assertRaises(vault.VaultError):
            vault.open_shared_entry(self.shared, self.other_private, KEY_PASSPHRASE)

    def test_wrong_private_key_passphrase_is_rejected(self):
        self.share()
        with self.assertRaises(vault.VaultError):
            vault.open_shared_entry(self.shared, self.private, "incorrect passphrase")

    def test_changed_ciphertext_nonce_and_wrapped_key_are_rejected(self):
        self.share()
        original = json.loads(self.shared.read_bytes())
        for field in ("ciphertext", "nonce", "wrapped_key"):
            with self.subTest(field=field):
                document = copy.deepcopy(original)
                location = document["header"] if field == "wrapped_key" else document
                value = bytearray(vault.b64decode(location[field]))
                value[0] ^= 1
                location[field] = vault.b64encode(value)
                raw = vault.canonical_json(document)
                self.shared.write_bytes(raw)
                with self.assertRaises(vault.VaultError):
                    vault.open_shared_entry(self.shared, self.private, KEY_PASSPHRASE)
                self.assertEqual(self.shared.read_bytes(), raw)

    def test_fresh_key_and_nonce_for_each_export(self):
        self.share()
        second_path = self.directory / "second.share.json"
        vault.share_entry(SITE, ENTRY, self.public, second_path)
        first = json.loads(self.shared.read_bytes())
        second = json.loads(second_path.read_bytes())
        self.assertNotEqual(first["header"]["wrapped_key"], second["header"]["wrapped_key"])
        recipient = serialization.load_pem_private_key(
            self.private.read_bytes(), password=KEY_PASSPHRASE.encode(),
        )
        first_key = recipient.decrypt(vault.b64decode(first["header"]["wrapped_key"]), vault.sharing_padding())
        second_key = recipient.decrypt(vault.b64decode(second["header"]["wrapped_key"]), vault.sharing_padding())
        self.assertEqual(len(first_key), 32)
        self.assertEqual(len(second_key), 32)
        self.assertNotEqual(first_key, second_key)
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])
        self.assertEqual(
            vault.open_shared_entry(second_path, self.private, KEY_PASSPHRASE),
            (SITE, ENTRY),
        )

    def test_existing_share_file_is_not_overwritten(self):
        sentinel = b"keep this existing file"
        self.shared.write_bytes(sentinel)
        with self.assertRaises(vault.VaultError):
            self.share()
        self.assertEqual(self.shared.read_bytes(), sentinel)

    def test_invalid_share_format_is_rejected(self):
        self.share()
        original = json.loads(self.shared.read_bytes())
        cases = []
        for field, value in (("version", 2), ("format", "unknown"), ("algorithm", "RSA-raw")):
            document = copy.deepcopy(original)
            document["header"][field] = value
            cases.append(vault.canonical_json(document))
        cases.extend((b"{broken", b"[]", self.shared.read_bytes() + b" "))
        for raw in cases:
            with self.subTest(raw=raw[:100]):
                self.shared.write_bytes(raw)
                with self.assertRaises(vault.VaultError):
                    vault.open_shared_entry(self.shared, self.private, KEY_PASSPHRASE)

    def test_full_cli_share_and_open_without_recipient_vault(self):
        vault_path = self.directory / "sender.vault.json"
        vault.initialize(vault_path, MASTER)
        header, key, entries = vault.unlock(vault_path, MASTER)
        entries[SITE] = ENTRY
        vault.save(vault_path, header, key, entries)
        before = vault_path.read_bytes()
        status, _, error = self.cli(
            "share", SITE, "--public-key", str(self.public), "--out", str(self.shared),
            secrets=[MASTER], vault_path=vault_path,
        )
        self.assertEqual(status, 0, error)
        self.assertEqual(vault_path.read_bytes(), before)
        status, output, error = self.cli(
            "open-share", str(self.shared), "--private-key", str(self.private),
            secrets=[KEY_PASSPHRASE],
        )
        self.assertEqual(status, 0, error)
        for value in (SITE, *ENTRY.values()):
            self.assertIn(value, output)
        self.assertFalse((self.directory / "nonexistent-vault.json").exists())

    def test_cli_bad_private_passphrase_exposes_no_entry(self):
        self.share()
        status, output, error = self.cli(
            "open-share", str(self.shared), "--private-key", str(self.private),
            secrets=["incorrect passphrase"],
        )
        self.assertEqual(status, 1)
        self.assertTrue(error)
        self.assertEqual(output, "")
        for value in (SITE, *ENTRY.values()):
            self.assertNotIn(value, error)


class KeyGenerationAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.private = self.directory / "private.pem"
        self.public = self.directory / "public.pem"

    def test_keygen_cli_and_confirmation(self):
        arguments = ["keygen", "--private", str(self.private), "--public", str(self.public)]
        with patch("vault.getpass.getpass", side_effect=[KEY_PASSPHRASE, "mismatch"]):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(vault.main(arguments), 1)
        self.assertFalse(self.private.exists())
        self.assertFalse(self.public.exists())
        with patch("vault.getpass.getpass", side_effect=[KEY_PASSPHRASE, KEY_PASSPHRASE]):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(vault.main(arguments), 0)
        self.assertTrue(self.private.is_file())
        self.assertTrue(self.public.is_file())

    def test_existing_private_or_public_key_is_not_overwritten(self):
        for existing in (self.private, self.public):
            with self.subTest(existing=existing.name):
                existing.write_bytes(b"existing key file")
                with self.assertRaises(vault.VaultError):
                    vault.generate_sharing_keys(self.private, self.public, KEY_PASSPHRASE)
                self.assertEqual(existing.read_bytes(), b"existing key file")
                other = self.public if existing == self.private else self.private
                self.assertFalse(other.exists())
                existing.unlink()

    def test_identical_key_destinations_are_rejected(self):
        with self.assertRaises(vault.VaultError):
            vault.generate_sharing_keys(self.private, self.private, KEY_PASSPHRASE)
        self.assertFalse(self.private.exists())

    def test_short_private_key_passphrase_is_rejected(self):
        with self.assertRaises(vault.VaultError):
            vault.generate_sharing_keys(self.private, self.public, "short")
        self.assertFalse(self.private.exists())
        self.assertFalse(self.public.exists())

    def test_oversized_private_key_passphrase_is_rejected_before_key_generation(self):
        for passphrase in ("x" * 1024, "密" * 342):
            with self.subTest(length=len(passphrase)), patch("vault.rsa.generate_private_key") as generate:
                with self.assertRaises(vault.VaultError):
                    vault.generate_sharing_keys(self.private, self.public, passphrase)
                generate.assert_not_called()
        self.assertFalse(self.private.exists())
        self.assertFalse(self.public.exists())


if __name__ == "__main__":
    unittest.main()
