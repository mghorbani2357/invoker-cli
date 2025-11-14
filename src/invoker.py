import ast
import hashlib
import importlib
import importlib.util
import os
import shutil
import types
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
from typing import NamedTuple

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


def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a secure 256-bit key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password (bytes): The password in bytes (UTF-8 encoded usually).
        salt (bytes): A unique salt value for this derivation.

    Returns:
        bytes: A derived key of length KEY_SIZE.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(input_path: str, password: str) -> bytes:
    """
    Encrypts a file using AES-GCM with a key derived from the given password.

    Args:
        input_path (str): Path to the plaintext file.
        password (str): Password to derive the encryption key.

    Returns:
        bytes: Concatenated bytes of salt + nonce + ciphertext.

    Raises:
        FileNotFoundError: If the input file doesn't exist.
        ValueError: If the file is empty or unreadable.
    """
    path = Path(input_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {input_path}")

    plaintext = path.read_bytes()
    if not plaintext:
        raise ValueError("Cannot encrypt an empty file")

    # Generate salt and nonce securely
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Derive key from password
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)

    # Encrypt
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Return complete encrypted payload
    return salt + nonce + ciphertext


def decrypt_file(encrypted_path: str, password: str) -> bytes:
    """
    Decrypts a file encrypted with AES-GCM and a derived key.

    Args:
        encrypted_path (str): Path to the encrypted file.
        password (str): Password used for key derivation.

    Returns:
        bytes: The decrypted plaintext content.

    Raises:
        IncorrectPasswordOrCorruptedFile: If decryption fails due to a wrong password or corrupted file.
        FileNotFoundError: If the input file doesn't exist.
        ValueError: If the file structure is invalid.
    """
    path = Path(encrypted_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {encrypted_path}")

    data = path.read_bytes()

    if len(data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Invalid encrypted file format")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise IncorrectPasswordOrCorruptedFile(
            "Decryption failed: incorrect password or corrupted file"
        ) from e

    return plaintext


def sha256sum(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.sha256(f.read()).hexdigest()


def find_slots(slot_identifier) -> list[Slot]:
    slots_list = list_slots()
    results = list()
    for slot in slots_list:
        if slot.name.removesuffix('.enc') == slot_identifier or slot.hash.startswith(slot_identifier):
            results.append(slot)

    return results


def mssrio(slots):  # Make sure search result is one
    if len(slots) > 1:
        raise DuplicateSlotID(f"Multiple identifiers found with provided prefix.")
    elif len(slots) == 0:
        raise InvalidSlotID(f"Unable to find the slot with provided prefix.")


def delete_slot(slot_identifier):
    candidate_slots = find_slots(slot_identifier)
    mssrio(candidate_slots)
    os.remove(candidate_slots[0].path)


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


def validate_encrypted_module(path, password) -> bool:
    if os.path.exists(path):

        try:
            context = decrypt_file(str(path), password)
            ast.parse(context)
            module_name = "module"
            module = types.ModuleType(module_name)
            namespace = module.__dict__
            exec(context, namespace)
            if hasattr(module, 'invoke'):
                return True
            raise InvalidModule(f"Module does not have `invoke` method")

        except:
            raise InvalidModule(f"Invalid Context")
    else:
        raise FileNotFoundError(f"File '{path}' does not exists")


class InvalidModule(Exception):
    pass


def validate_module(path) -> bool:
    if os.path.exists(path):
        spec = importlib.util.spec_from_file_location('slot', path)
        module = importlib.util.module_from_spec(spec)

        if spec.loader:
            try:
                spec.loader.exec_module(module)
                if hasattr(module, 'invoke'):
                    return True
                else:
                    raise InvalidModule(f"Module does not have `invoke` method")
            except SyntaxError as e:
                raise InvalidModule(f"{str(e)}")
        else:
            raise InvalidModule(f"No loader found for {path}")
    else:
        raise FileNotFoundError(f"File '{path}' does not exists")


def add_slot(path, password=None):
    if password is not None:
        name, extension = os.path.splitext(os.path.basename(path))
        buffer = encrypt_file(path, password)
        out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{name}.enc{extension}'
    else:
        out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{os.path.basename(path)}'
        with open(path, 'rb') as f_in:
            buffer = f_in.read()
    if len(find_slots(hashlib.sha256(buffer).hexdigest())) == 0:
        with open(out_put_slot_path, 'wb') as f_out:
            f_out.write(buffer)
    else:
        raise InvalidModule(f"Slot already exists")


def get_version():
    try:
        return version("Invoker-CLI")
    except PackageNotFoundError:
        return "unknown"
