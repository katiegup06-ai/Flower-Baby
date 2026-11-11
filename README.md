# Flower-Baby

**Project:** Command-line password manager 

**Team**
| Chinese Name | English Name | Student ID |
|--------------|--------------|------------|
| 张馨月       | Jacinda      | 2023905322 |
| 郭可馨       | Katie        | 2023905318 |
| 边红瑞       | Rae/Hongrui  | 2023905334 |

## About the project

We built a small password manager that runs in the terminal. The idea is simple: instead of keeping website passwords in a plain text file, we protect them with one master password. After unlocking the vault, a user can add an account, list saved accounts, read a password, or delete an entry. The program can also generate a random password.

We kept the project local and command-line based. There is no website, database server, or GUI. This helped us focus on choosing the right cryptographic tools and understanding what they protect.

## Getting started

Use **Python 3.10 or newer** and install the dependencies:

```bash
python -m pip install -r requirements.txt
```

Then run the commands from the project folder:

```bash
python vault.py init
python vault.py add github --user alice
python vault.py list
python vault.py get github
python vault.py gen --length 20
python vault.py delete github
```

`init` asks you to choose and confirm a master password of at least 16 characters. The other vault commands ask for it again when needed. `add` also asks for the entry's password without displaying what you type. The `gen` command does not need the master password.

The default vault file is `vault.json`. To practise without using your normal vault, pass a different file name **before** the command:

```bash
python vault.py --vault demo.json init
python vault.py --vault demo.json add example --user demo
python vault.py --vault demo.json get example
```

Use fictional credentials when demonstrating the program. Do not put passwords directly into shell commands or screenshots.

## How we protect the passwords

### 1. Checking the master password with Argon2id

When the vault is created, we use `argon2-cffi` to hash the master password. The file keeps an encoded `$argon2id$...` value, not the original password. The hash includes a random salt and the parameters needed for verification. When someone tries to open the vault, we verify their input against this value.

We chose **Argon2id** rather than ordinary SHA-256 because password guessing is the main risk here. SHA-256 is designed to be fast; an attacker could try many guesses quickly. Argon2id deliberately uses time and memory to make each guess more expensive. We also do not encrypt the master password with AES: we only need to check it, not recover it later.

### 2. Deriving an AES key from the master password

A password hash is not the same thing as an encryption key. We use the `cryptography` library's **Argon2id key derivation function** with a separate random salt to derive a 256-bit AES key from the master password.

We do not save that AES key in a file. If the vault and its key were saved side by side, stealing both files could be enough to read everything. With key derivation, the user can regenerate the same key by entering the correct master password, while the stored salt and parameters can safely remain public. The salt used for key derivation is separate from the one embedded in the master-password hash.

### 3. Encrypting the vault with AES-GCM

We use **AES-256-GCM** from `cryptography` to encrypt the saved entries, including the site names, usernames, and passwords. AES keeps that information confidential; GCM adds an authentication check so that modified ciphertext is rejected instead of being silently decrypted into untrusted data.

Every save uses a fresh 12-byte nonce. The nonce is not a secret, but it must not be reused with the same AES key. The file also stores the authentication tag as part of the encrypted output. We authenticate important header information as additional authenticated data (AAD), so altering that information is also detected.

### 4. Generating passwords with `secrets`

The password generator uses Python's `secrets.choice` to select characters from uppercase and lowercase letters, digits, and punctuation. The default length is 20 characters, and the user can choose another length from 16 to 1024.

We used `secrets` instead of `random` because a password needs unpredictable randomness. The standard `random` module is useful for simulations, but it is not intended to generate security-sensitive values.

## Optional bonus: sharing one entry

We also implemented **Bonus A**, which lets Alice share one saved entry with Bob using Bob's public key. It uses hybrid encryption: a fresh AES-256-GCM key encrypts the entry, and RSA-OAEP with SHA-256 encrypts that temporary AES key. Bob uses his private key to open the shared file. This avoids trying to encrypt a large entry directly with RSA.

To try it with test data:

```bash
python vault.py keygen --private bob-private.pem --public bob-public.pem
python vault.py share github --public-key bob-public.pem --out github.share.json
python vault.py open-share github.share.json --private-key bob-private.pem
```

These commands assume that a `github` entry already exists. The generated private key is protected with a separate passphrase. **Only Bob's public key should be shared**; Bob must keep his private key and its passphrase private. Alice should confirm that the public key really belongs to Bob before using it.

This bonus protects the shared entry from people who do not have Bob's private key, but it **does not prove who sent it**. We did not implement a digital signature. We did not implement Bonus B (breached-password checking).

## What the tool protects — and what it doesn't

If someone copies the vault file, they should not be able to read the entries directly: the file contains encrypted data, not plaintext passwords or a stored AES key. They can still try to guess the master password offline, so choosing a strong master password matters.

Our tool does **not** protect against malware or keyloggers on the computer, someone seeing the screen or terminal output, a weak master password, or someone deleting or replacing the whole vault file. It also does not provide automatic backups, password recovery, or protection against multiple programs editing the same vault at once. If the master password is forgotten, the saved entries cannot be recovered by the program.

## Testing

We tested the project using Python's built-in `unittest` framework. The test files are `tests/test_vault.py` and `tests/test_sharing.py`.

Run the tests from the project folder:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Our test run produced the following result:

```text
Ran 35 tests in 11.976s

OK
```

All **35 tests passed**, with no failures or errors. The tests cover the everyday vault commands, password hashing, persistent encryption, wrong-password handling, corruption and tampering checks, password generation, and the RSA sharing feature. They also check that the share cannot be opened with the wrong private key or passphrase. The tests use temporary files and fictional credentials instead of real accounts.

These results show that the tested cases worked in our environment; they are not a complete security audit.

## Team members and work distribution

We split the work into three main parts. We also check the main features together so that everyone understands how the program works.

| Member | Main responsibility |
| --- | --- |
| **Bian Hongrui** | Master-password security (Argon2id), key derivation, and AES-256-GCM encryption and decryption. |
| **Guo Kexin** | Command-line interface (`init`, `add`, `list`, `get`, `delete`, `gen`), random password generation, saving and loading vault data, and error handling. |
| **Zhang Xinyue** | Bonus A: RSA-OAEP secure sharing, key-pair generation, sharing/decryption workflow, testing, and README documentation. |
