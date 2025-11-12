import ast
import ctypes
import hashlib
import os
import shutil
import subprocess
import sys
import types

from importlib.metadata import version, PackageNotFoundError
from typing import NamedTuple
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12  # GCM standard
KEY_SIZE = 32  # 256-bit AES
PBKDF2_ITERATIONS = 200_000

INVOKER_HOME_DIR = f'{os.path.expanduser("~")}/.invoker'
INVOKER_SLOTS_DIR = f'{INVOKER_HOME_DIR}/slots'


class Slot(NamedTuple):
    index: int
    name: str
    path: Path
    hash: str


class DuplicateSlotID(Exception):
    pass


class InvalidSlotID(Exception):
    pass


class PasswordDoesNotProvided(Exception):
    pass


class IncorrectPasswordOrCorruptedFile(Exception):
    pass


if os.name == 'nt':
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)


def clear_cli():
    if os.name == 'nt':
        sys.stdout.write('\x1b[?1049h')
        sys.stdout.flush()
    else:
        subprocess.run('tput smcup', shell=True)


def wipe_out():
    if os.name == 'nt':
        sys.stdout.write('\x1b[?1049l')
        sys.stdout.flush()
    else:
        subprocess.run('tput rmcup', shell=True)


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a secure 256-bit key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(input_path: str, password: str):
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return salt + nonce + ciphertext


def decrypt_file(encrypted_path: str, password: str):
    with open(encrypted_path, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise IncorrectPasswordOrCorruptedFile("Decryption failed: incorrect password or corrupted file")
    return plaintext


def sha256sum(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.sha256(f.read()).hexdigest()


def find_slot(slot_identifier) -> Path:
    slots_list = list_slots()
    results = list()
    for slot in slots_list:
        if slot.name.removesuffix('.enc') == slot_identifier or slot.hash.startswith(slot_identifier):
            results.append(slot.path)
    if len(results) == 1:
        return results[0]
    elif len(results) > 1:
        raise DuplicateSlotID(f"Error: Multiple identifiers found with provided prefix: {slot_identifier}")

    raise InvalidSlotID(f"Error: Unable to find the slot: {slot_identifier}")


def delete_slot(slot_identifier):
    os.remove(find_slot(slot_identifier))


def list_slots() -> list[Slot]:
    slots_list = list()

    path = Path(INVOKER_SLOTS_DIR)
    for index, path in enumerate(path.glob('*')):
        name, ext = os.path.splitext(os.path.basename(path))
        slots_list.append(Slot(index, name, path, sha256sum(path)))

    return slots_list


def invoke_slot(slot_path, password=None):
    namespace = {}

    if password is not None:
        exec(decrypt_file(str(slot_path), password), namespace)
    else:
        exec(open(str(slot_path)).read(), namespace)

    namespace['invoke']()


def save_slot(slot_path, save_path, password=None):
    if password is not None:
        with open(save_path, 'wb') as f_out:
            f_out.write(decrypt_file(str(slot_path), password))
    else:
        shutil.copy(slot_path, save_path)


def check_module(context) -> bool:
    try:
        ast.parse(context)
        module_name = "module"
        module = types.ModuleType(module_name)
        namespace = module.__dict__
        exec(context, namespace)
        if hasattr(module, 'invoke'):
            return True
        return False
    except:
        return False


def get_version():
    try:
        return version("Invoker-CLI")
    except PackageNotFoundError:
        return "unknown"

# Todo:
#   - review tests
#   - check for security enchantments
