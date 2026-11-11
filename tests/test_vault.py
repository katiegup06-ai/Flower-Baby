"""Acceptance tests with disposable fake credentials, never real passwords."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import string
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vault


MASTER = "test-only long master passphrase"
FAKE_ENTRY = {"username": "alice-example", "password": "fake-entry-secret-123!"}


class VaultAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "vault.json"
        vault.initialize(self.path, MASTER)

    def command(self, *args, secrets=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("vault.getpass.getpass", side_effect=secrets):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = vault.main(["--vault", str(self.path), *args])
        return status, stdout.getvalue(), stderr.getvalue()

    def populate(self):
        return self.command("add", "github-example", "--user", FAKE_ENTRY["username"],
                            secrets=[MASTER, FAKE_ENTRY["password"]])

    def test_full_cli_workflow_and_persistence(self):
        self.assertEqual(self.populate()[0], 0)
        status, output, _ = self.command("list", secrets=[MASTER])
        self.assertEqual(status, 0)
        self.assertIn("github-example", output)
        self.assertIn(FAKE_ENTRY["username"], output)
        self.assertNotIn(FAKE_ENTRY["password"], output)
        status, output, _ = self.command("get", "github-example", secrets=[MASTER])
        self.assertEqual(status, 0)
        self.assertIn(FAKE_ENTRY["password"], output)
        # Independent unlock reconstructs the key from disk metadata + master.
        self.assertEqual(vault.unlock(self.path, MASTER)[2]["github-example"], FAKE_ENTRY)
        self.assertEqual(self.command("delete", "github-example", secrets=[MASTER])[0], 0)
        self.assertEqual(vault.unlock(self.path, MASTER)[2], {})

    def test_verifier_and_no_plaintext_or_key_file(self):
        self.populate()
        document = json.loads(self.path.read_bytes())
        self.assertTrue(document["header"]["master_hash"].startswith("$argon2id$"))
        raw = self.path.read_bytes()
        for secret in (MASTER, "github-example", *FAKE_ENTRY.values()):
            self.assertNotIn(secret.encode(), raw)
        self.assertEqual({p.name for p in self.path.parent.iterdir()}, {"vault.json"})

    def test_wrong_master_rejected_without_writing(self):
        original = self.path.read_bytes()
        status, _, error = self.command("list", secrets=["incorrect master"])
        self.assertEqual(status, 1)
        self.assertIn("Wrong master password", error)
        self.assertEqual(self.path.read_bytes(), original)

    def test_ciphertext_one_byte_tamper_fails_loudly(self):
        document = json.loads(self.path.read_bytes())
        ciphertext = bytearray(vault.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 1
        document["ciphertext"] = vault.b64encode(ciphertext)
        tampered = vault.canonical_json(document)
        self.path.write_bytes(tampered)
        status, output, error = self.command("list", secrets=[MASTER])
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn("Authentication failed", error)
        self.assertEqual(self.path.read_bytes(), tampered)

    def test_raw_file_single_byte_tamper(self):
        raw = bytearray(self.path.read_bytes())
        index = raw.index(b'"ciphertext":"') + len(b'"ciphertext":"')
        raw[index] = ord("B") if raw[index] == ord("A") else ord("A")
        self.path.write_bytes(raw)
        self.assertEqual(self.command("list", secrets=[MASTER])[0], 1)

    def test_nonce_and_metadata_tampering_rejected(self):
        original = self.path.read_bytes()
        for field in ("nonce", "salt", "hash"):
            with self.subTest(field=field):
                document = json.loads(original)
                if field == "nonce":
                    document["nonce"] = vault.b64encode(bytes(12))
                elif field == "salt":
                    document["header"]["kdf"]["salt"] = vault.b64encode(bytes(16))
                else:
                    encoded = document["header"]["master_hash"]
                    document["header"]["master_hash"] = encoded[:-1] + ("A" if encoded[-1] != "A" else "B")
                self.path.write_bytes(vault.canonical_json(document))
                self.assertEqual(self.command("list", secrets=[MASTER])[0], 1)

    def test_untrusted_costs_rejected_before_crypto(self):
        original = json.loads(self.path.read_bytes())
        for field in ("kdf", "master_hash"):
            with self.subTest(field=field):
                document = copy.deepcopy(original)
                if field == "kdf":
                    document["header"]["kdf"]["memory_kib"] = 999999999
                else:
                    document["header"]["master_hash"] = document["header"]["master_hash"].replace("m=65536", "m=999999999")
                self.path.write_bytes(vault.canonical_json(document))
                with patch("vault.HASHER") as hasher:
                    self.assertEqual(self.command("list", secrets=[MASTER])[0], 1)
                    hasher.verify.assert_not_called()

    def test_new_nonce_each_save_and_independent_salts(self):
        before = json.loads(self.path.read_bytes())
        self.populate()
        after = json.loads(self.path.read_bytes())
        self.assertNotEqual(before["nonce"], after["nonce"])
        self.assertEqual(before["header"], after["header"])
        other = self.path.parent / "other.vault.json"
        vault.initialize(other, MASTER)
        second = json.loads(other.read_bytes())
        self.assertNotEqual(before["header"]["kdf"]["salt"], second["header"]["kdf"]["salt"])
        self.assertNotEqual(before["header"]["master_hash"], second["header"]["master_hash"])

    def test_existing_vault_and_entries_not_overwritten(self):
        self.populate()
        original = self.path.read_bytes()
        with self.assertRaises(vault.VaultError):
            vault.initialize(self.path, MASTER)
        status, _, _ = self.command("add", "github-example", "--user", "someone-else", secrets=[MASTER])
        self.assertEqual(status, 1)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.command("delete", "missing", secrets=[MASTER])[0], 1)
        self.assertEqual(self.path.read_bytes(), original)

    def test_broken_or_reformatted_file_rejected(self):
        original = self.path.read_bytes()
        for content in (b"{broken", original + b" ", b"[]"):
            with self.subTest(content=content[:20]):
                self.path.write_bytes(content)
                self.assertEqual(self.command("list", secrets=[MASTER])[0], 1)
                self.assertEqual(self.path.read_bytes(), content)

    def test_failed_save_preserves_old_file_and_removes_temp(self):
        original = self.path.read_bytes()
        header, key, entries = vault.unlock(self.path, MASTER)
        entries["example"] = FAKE_ENTRY
        with patch("vault.os.replace", side_effect=OSError("simulated replace failure")):
            with self.assertRaises(OSError):
                vault.save(self.path, header, key, entries)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.path.parent.glob(".vault-*.tmp")), [])

    def test_non_ascii_verifier_is_rejected_cleanly(self):
        document = json.loads(self.path.read_bytes())
        encoded = document["header"]["master_hash"]
        document["header"]["master_hash"] = encoded[:-1] + "é"
        self.path.write_bytes(vault.canonical_json(document))
        status, _, error = self.command("list", secrets=[MASTER])
        self.assertEqual(status, 1)
        self.assertIn("Invalid master-password hash", error)


class PasswordGeneratorTests(unittest.TestCase):
    def test_length_and_alphabet(self):
        alphabet = set(string.ascii_letters + string.digits + string.punctuation)
        for length in (16, 20, 64, 1024):
            password = vault.generate_password(length)
            self.assertEqual(len(password), length)
            self.assertTrue(set(password) <= alphabet)

    def test_invalid_lengths(self):
        for length in (-1, 0, 15, 1025):
            with self.subTest(length=length), self.assertRaises(vault.VaultError):
                vault.generate_password(length)

    def test_actual_command_entrypoint(self):
        script = Path(vault.__file__).resolve()
        result = subprocess.run(
            [sys.executable, str(script), "gen", "--length", "20"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.strip()), 20)


class InitializationAndInputTests(unittest.TestCase):
    def test_init_command_and_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.vault.json"
            with patch("vault.getpass.getpass", side_effect=[MASTER, "mismatch"]):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(vault.main(["--vault", str(path), "init"]), 1)
            self.assertFalse(path.exists())
            with patch("vault.getpass.getpass", side_effect=[MASTER, MASTER]):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(vault.main(["--vault", str(path), "init"]), 0)
            self.assertEqual(vault.unlock(path, MASTER)[2], {})

    def test_too_short_master_does_not_create_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.vault.json"
            with self.assertRaises(vault.VaultError):
                vault.initialize(path, "short")
            self.assertFalse(path.exists())

    def test_echoed_input_fallback_is_refused(self):
        import warnings

        def fallback(prompt):
            warnings.warn("Cannot hide input", vault.getpass.GetPassWarning)
            self.fail("Echoed password fallback must not run")

        with patch("vault.getpass.getpass", side_effect=fallback):
            with self.assertRaises(vault.VaultError):
                vault.read_secret("Hidden password: ")


if __name__ == "__main__":
    unittest.main()
