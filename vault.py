"""Small, local teaching project: Argon2id + AES-256-GCM password vault."""

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import string
import sys
import tempfile
import warnings

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import HashingError, InvalidHashError, VerificationError
from argon2.low_level import Type
from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# Version 1 accepts exactly these costs; never trust cost values in an input file.
MEMORY_KIB = 64 * 1024
ITERATIONS = 3
LANES = 4
SALT_BYTES = 16
KEY_BYTES = 32
NONCE_BYTES = 12
MAX_FILE_BYTES = 10 * 1024 * 1024
KDF_CONFIG = {
    "name": "argon2id", "memory_kib": MEMORY_KIB,
    "iterations": ITERATIONS, "parallelism": LANES,
}
HASHER = PasswordHasher(
    time_cost=ITERATIONS, memory_cost=MEMORY_KIB, parallelism=LANES,
    hash_len=KEY_BYTES, salt_len=SALT_BYTES, type=Type.ID,
)
ALPHABET = string.ascii_letters + string.digits + string.punctuation
SHARE_FORMAT = {
    "format": "password-manager-share", "version": 1,
    "algorithm": "RSA-OAEP-SHA256+AES-256-GCM",
}


class VaultError(Exception):
    """An expected failure that the CLI can explain without a traceback."""


def canonical_json(value):
    """Stable bytes used for both the file format and authenticated header."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def b64encode(value):
    return base64.b64encode(value).decode("ascii")


def b64decode(value, expected_length=None):
    try:
        if not isinstance(value, str):
            raise ValueError("not a string")
        decoded = base64.b64decode(value, validate=True)
        if b64encode(decoded) != value:
            raise ValueError("noncanonical base64")
        if expected_length is not None and len(decoded) != expected_length:
            raise ValueError("wrong length")
        return decoded
    except (ValueError, binascii.Error) as exc:
        raise VaultError("Invalid vault encoding or field length.") from exc


def derive_key(master_password, salt):
    """This output is secret: keep it in memory and never put it in the file."""
    return Argon2id(
        salt=salt, length=KEY_BYTES, iterations=ITERATIONS,
        lanes=LANES, memory_cost=MEMORY_KIB,
    ).derive(master_password.encode("utf-8"))


def validate_header(header):
    if not isinstance(header, dict) or set(header) != {"version", "master_hash", "kdf"}:
        raise VaultError("Invalid vault header.")
    if type(header["version"]) is not int or header["version"] != 1:
        raise VaultError("Unsupported vault version.")
    kdf = header["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != set(KDF_CONFIG) | {"salt"}:
        raise VaultError("Invalid KDF settings.")
    for field, expected in KDF_CONFIG.items():
        if type(kdf[field]) is not type(expected) or kdf[field] != expected:
            raise VaultError("Unsupported KDF settings; file may be tampered with.")
    b64decode(kdf["salt"], SALT_BYTES)

    # PasswordHasher.verify trusts the PHC string's costs: check them first.
    encoded = header["master_hash"]
    if not isinstance(encoded, str) or not encoded.isascii() or len(encoded) > 256:
        raise VaultError("Invalid master-password hash.")
    try:
        params = extract_parameters(encoded)
    except (InvalidHashError, ValueError) as exc:
        raise VaultError("Invalid master-password hash.") from exc
    if (
        params.type != Type.ID or params.version != 19
        or params.memory_cost != MEMORY_KIB or params.time_cost != ITERATIONS
        or params.parallelism != LANES or params.salt_len != SALT_BYTES
        or params.hash_len != KEY_BYTES
    ):
        raise VaultError("Unsupported master-hash settings.")


def read_document(path):
    # Bounded read prevents an oversized input file from filling memory.
    with path.open("rb") as source:
        raw = source.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise VaultError("Vault file is too large.")
    try:
        document = json.loads(raw)
        if canonical_json(document) != raw:
            raise VaultError("Vault format changed. Do not edit or reformat the file.")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VaultError("Vault is damaged or is not valid JSON.") from exc
    if not isinstance(document, dict) or set(document) != {"header", "nonce", "ciphertext"}:
        raise VaultError("Invalid vault structure.")
    validate_header(document["header"])
    b64decode(document["nonce"], NONCE_BYTES)
    if len(b64decode(document["ciphertext"])) < 16:
        raise VaultError("Vault ciphertext is missing its authentication tag.")
    return document


def validate_entries(entries):
    if not isinstance(entries, dict):
        raise VaultError("Invalid decrypted vault structure.")
    for site, entry in entries.items():
        if not isinstance(site, str) or not isinstance(entry, dict):
            raise VaultError("Invalid entry.")
        if set(entry) != {"username", "password"}:
            raise VaultError("Invalid entry fields.")
        if not all(isinstance(value, str) for value in entry.values()):
            raise VaultError("Invalid entry values.")


def unlock(path, master_password):
    document = read_document(path)
    header = document["header"]
    try:
        HASHER.verify(header["master_hash"], master_password)
    except (VerificationError, InvalidHashError) as exc:
        raise VaultError("Wrong master password, or master hash was changed.") from exc
    key = derive_key(master_password, b64decode(header["kdf"]["salt"], SALT_BYTES))
    try:
        plaintext = AESGCM(key).decrypt(
            b64decode(document["nonce"], NONCE_BYTES),
            b64decode(document["ciphertext"]), canonical_json(header),
        )
    except InvalidTag as exc:
        # Never recover by silently returning an empty vault.
        raise VaultError("Authentication failed: vault was damaged or tampered with.") from exc
    try:
        entries = json.loads(plaintext)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VaultError("Invalid decrypted data.") from exc
    validate_entries(entries)
    return header, key, entries


def encrypted_bytes(header, key, entries):
    validate_entries(entries)
    # A fresh nonce is required on EVERY write with the same key.
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, canonical_json(entries), canonical_json(header))
    result = canonical_json({
        "header": header, "nonce": b64encode(nonce), "ciphertext": b64encode(ciphertext),
    })
    if len(result) > MAX_FILE_BYTES:
        raise VaultError("Vault would exceed the size limit.")
    return result


def initialize(path, master_password):
    if path.exists():
        raise VaultError("Vault already exists; initialization will not overwrite it.")
    if len(master_password) < 16:
        raise VaultError("Use a master passphrase of at least 16 characters.")
    salt = secrets.token_bytes(SALT_BYTES)
    header = {
        "version": 1,
        # This verifier has its own random salt, generated by argon2-cffi.
        "master_hash": HASHER.hash(master_password),
        "kdf": {**KDF_CONFIG, "salt": b64encode(salt)},
    }
    content = encrypted_bytes(header, derive_key(master_password, salt), {})
    try:
        # Exclusive creation also prevents accidental overwrite after our check.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise VaultError("Vault already exists.") from exc
    with os.fdopen(fd, "wb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def save(path, header, key, entries):
    content = encrypted_bytes(header, key, entries)
    # Only ciphertext touches this temporary file. Replace only after a full write.
    fd, temporary = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def generate_password(length=20):
    if not 16 <= length <= 1024:
        raise VaultError("Password length must be between 16 and 1024.")
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def read_key_bytes(path):
    with path.open("rb") as source:
        data = source.read(64 * 1024 + 1)
    if len(data) > 64 * 1024:
        raise VaultError("Key file is too large.")
    return data


def write_new_file(path, content):
    """For exports and keys: never overwrite an existing destination."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise VaultError(f"Output already exists: {path}") from exc
    with os.fdopen(fd, "wb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def load_sharing_public_key(path):
    try:
        key = serialization.load_pem_public_key(read_key_bytes(path))
    except (ValueError, TypeError) as exc:
        raise VaultError("Invalid recipient public key; expected an RSA PEM public key.") from exc
    if not isinstance(key, rsa.RSAPublicKey) or not 3072 <= key.key_size <= 8192:
        raise VaultError("Sharing requires an RSA public key of 3072 to 8192 bits.")
    return key


def public_key_fingerprint(key):
    # SHA-256 identifies a public key here; it is not used to hash passwords.
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def generate_sharing_keys(private_path, public_path, passphrase):
    if private_path.resolve() == public_path.resolve():
        raise VaultError("Private and public key files must have different names.")
    if private_path.exists() or public_path.exists():
        raise VaultError("Key output already exists; key generation will not overwrite it.")
    if len(passphrase) < 16:
        raise VaultError("Use a private-key passphrase of at least 16 characters.")
    password_bytes = passphrase.encode("utf-8")
    if len(password_bytes) > 1023:
        raise VaultError("Private-key passphrase must not exceed 1023 UTF-8 bytes.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password_bytes),
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    write_new_file(private_path, private_pem)
    write_new_file(public_path, public_pem)
    return public_key_fingerprint(public_key)


def sharing_padding():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def share_entry(site, entry, public_path, output_path):
    validate_entries({site: entry})
    if output_path.exists():
        raise VaultError("Share output already exists; choose a new file name.")
    public_key = load_sharing_public_key(public_path)
    # Independent per-export key: the vault's key is never shared or saved.
    export_key = AESGCM.generate_key(bit_length=256)
    header = {
        **SHARE_FORMAT,
        "wrapped_key": b64encode(public_key.encrypt(export_key, sharing_padding())),
    }
    nonce = secrets.token_bytes(NONCE_BYTES)
    payload = canonical_json({"site": site, **entry})
    ciphertext = AESGCM(export_key).encrypt(nonce, payload, canonical_json(header))
    content = canonical_json({
        "header": header, "nonce": b64encode(nonce), "ciphertext": b64encode(ciphertext),
    })
    if len(content) > MAX_FILE_BYTES:
        raise VaultError("Shared entry is too large.")
    write_new_file(output_path, content)
    return public_key_fingerprint(public_key)


def open_shared_entry(input_path, private_path, passphrase):
    with input_path.open("rb") as source:
        raw = source.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise VaultError("Share file is too large.")
    try:
        document = json.loads(raw)
        if canonical_json(document) != raw:
            raise ValueError("noncanonical share")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VaultError("Invalid or damaged share file.") from exc
    if not isinstance(document, dict) or set(document) != {"header", "nonce", "ciphertext"}:
        raise VaultError("Invalid share structure.")
    header = document["header"]
    if not isinstance(header, dict) or set(header) != set(SHARE_FORMAT) | {"wrapped_key"}:
        raise VaultError("Invalid share header.")
    for field, expected in SHARE_FORMAT.items():
        if type(header[field]) is not type(expected) or header[field] != expected:
            raise VaultError("Unsupported share format or algorithm.")
    wrapped_key = b64decode(header["wrapped_key"])
    nonce = b64decode(document["nonce"], NONCE_BYTES)
    ciphertext = b64decode(document["ciphertext"])
    try:
        private_key = serialization.load_pem_private_key(
            read_key_bytes(private_path), password=passphrase.encode("utf-8"),
        )
    except (ValueError, TypeError) as exc:
        raise VaultError("Cannot open private key: wrong passphrase or invalid encrypted key file.") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey) or not 3072 <= private_key.key_size <= 8192:
        raise VaultError("Sharing requires an RSA private key of 3072 to 8192 bits.")
    if len(wrapped_key) != (private_key.key_size + 7) // 8:
        raise VaultError("Share authentication failed: wrong recipient key or damaged share.")
    try:
        export_key = private_key.decrypt(wrapped_key, sharing_padding())
        if len(export_key) != KEY_BYTES:
            raise ValueError("wrong export key length")
        plaintext = AESGCM(export_key).decrypt(nonce, ciphertext, canonical_json(header))
    except (ValueError, InvalidTag) as exc:
        raise VaultError("Share authentication failed: wrong recipient key or tampered file.") from exc
    try:
        payload = json.loads(plaintext)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VaultError("Invalid shared entry data.") from exc
    if not isinstance(payload, dict) or set(payload) != {"site", "username", "password"}:
        raise VaultError("Invalid shared entry fields.")
    if not all(isinstance(value, str) for value in payload.values()):
        raise VaultError("Invalid shared entry values.")
    # Public-key encryption does not authenticate a sender; reject terminal controls.
    for field, value in payload.items():
        visible_text(value, field)
    return payload["site"], {"username": payload["username"], "password": payload["password"]}


def read_secret(prompt):
    # getpass normally falls back to echoed input; refuse that fallback.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning as exc:
            raise VaultError("Hidden input is unavailable. Run in a normal terminal.") from exc


def visible_text(value, field):
    if not value or any(not character.isprintable() for character in value):
        raise VaultError(f"{field} must be nonempty and contain no control characters.")
    return value


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault", type=Path, default=Path("vault.json"), help="vault file path")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create a new encrypted vault")
    add = commands.add_parser("add", help="add one site; prompt for its password")
    add.add_argument("site")
    add.add_argument("--user", required=True)
    commands.add_parser("list", help="list sites and usernames after unlocking")
    for name in ("get", "delete"):
        sub = commands.add_parser(name)
        sub.add_argument("site")
    generator = commands.add_parser("gen", help="generate a password without opening a vault")
    generator.add_argument("--length", type=int, default=20)
    keygen = commands.add_parser("keygen", help="create an encrypted RSA sharing keypair")
    keygen.add_argument("--private", type=Path, required=True)
    keygen.add_argument("--public", type=Path, required=True)
    share = commands.add_parser("share", help="encrypt one entry for a recipient public key")
    share.add_argument("site")
    share.add_argument("--public-key", type=Path, required=True)
    share.add_argument("--out", type=Path, required=True)
    opened = commands.add_parser("open-share", help="decrypt a share with your private key")
    opened.add_argument("input", type=Path)
    opened.add_argument("--private-key", type=Path, required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "gen":
            print(generate_password(args.length))
            return 0
        if args.command == "keygen":
            password = read_secret("Choose private-key passphrase (16+ characters): ")
            if password != read_secret("Confirm private-key passphrase: "):
                raise VaultError("Private-key passphrases do not match.")
            fingerprint = generate_sharing_keys(args.private, args.public, password)
            print(f"Created encrypted private key: {args.private}\nCreated public key: {args.public}")
            print(f"Public-key SHA256 fingerprint: {fingerprint}")
            return 0
        if args.command == "open-share":
            site, entry = open_shared_entry(
                args.input, args.private_key, read_secret("Private-key passphrase: "),
            )
            print(f"Site: {site}\nUsername: {entry['username']}\nPassword: {entry['password']}")
            return 0
        if args.command == "init":
            if args.vault.exists():
                raise VaultError("Vault already exists; initialization will not overwrite it.")
            master = read_secret("Choose master passphrase (16+ characters): ")
            if master != read_secret("Confirm master passphrase: "):
                raise VaultError("Master passphrases do not match.")
            initialize(args.vault, master)
            print(f"Created encrypted vault: {args.vault}")
            return 0
        if not args.vault.is_file():
            raise VaultError("Vault not found. Run 'python vault.py init' first.")
        header, key, entries = unlock(args.vault, read_secret("Master passphrase: "))
        if args.command == "add":
            site = visible_text(args.site, "Site")
            username = visible_text(args.user, "Username")
            if site in entries:
                raise VaultError("That site already exists. Use a different entry name.")
            password = read_secret("Password to store (hidden): ")
            visible_text(password, "Password")
            entries[site] = {"username": username, "password": password}
            save(args.vault, header, key, entries)
            print(f"Added: {site}")
        elif args.command == "list":
            if not entries:
                print("Vault is empty.")
            for site, entry in sorted(entries.items()):
                print(f"{site}\t{entry['username']}")
        elif args.command == "share":
            if args.site not in entries:
                raise VaultError("Entry not found.")
            fingerprint = share_entry(args.site, entries[args.site], args.public_key, args.out)
            print(f"Created encrypted share: {args.out}")
            print(f"Recipient public-key SHA256 fingerprint: {fingerprint}")
        elif args.command in ("get", "delete"):
            if args.site not in entries:
                raise VaultError("Entry not found.")
            if args.command == "get":
                entry = entries[args.site]
                print(f"Site: {args.site}\nUsername: {entry['username']}\nPassword: {entry['password']}")
            else:
                del entries[args.site]
                save(args.vault, header, key, entries)
                print(f"Deleted: {args.site}")
        return 0
    except (VaultError, OSError, HashingError, VerificationError, UnsupportedAlgorithm) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except MemoryError:
        print("Error: Not enough memory to complete this operation safely.", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
