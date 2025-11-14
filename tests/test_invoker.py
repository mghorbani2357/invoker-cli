import unittest
import tempfile

from src.invoker import *

def create_encrypted_file(plaintext: bytes, password: str, file_path: str):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    data = salt + nonce + ciphertext
    Path(file_path).write_bytes(data)
    return data

class TestDeriveKey(unittest.TestCase):
    def setUp(self):
        self.password = b"supersecret"
        self.salt = b"randomsalt"

    def test_returns_bytes(self):
        key = derive_key(self.password, self.salt)
        self.assertIsInstance(key, bytes, "Key should be bytes")

    def test_key_length(self):
        key = derive_key(self.password, self.salt)
        self.assertEqual(len(key), KEY_SIZE, "Key should be 256 bits (32 bytes) long")

    def test_deterministic_output(self):
        key1 = derive_key(self.password, self.salt)
        key2 = derive_key(self.password, self.salt)
        self.assertEqual(key1, key2, "Same input should yield same derived key")

    def test_different_password_changes_key(self):
        key1 = derive_key(self.password, self.salt)
        key2 = derive_key(b"anotherpassword", self.salt)
        self.assertNotEqual(key1, key2, "Different password should yield different key")

    def test_different_salt_changes_key(self):
        key1 = derive_key(self.password, self.salt)
        key2 = derive_key(self.password, b"othersalt")
        self.assertNotEqual(key1, key2, "Different salt should yield different key")

    def test_invalid_input_type(self):
        with self.assertRaises(TypeError):
            derive_key("notbytes", self.salt)  # password should be bytes
        with self.assertRaises(TypeError):
            derive_key(self.password, "notbytes")  # salt should be bytes

class TestEncryptFile(unittest.TestCase):

    def setUp(self):
        """Create a temporary plaintext file for testing."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.plaintext = b"Secret message for encryption"
        self.temp_file.write(self.plaintext)
        self.temp_file.close()
        self.password = "strongpassword"

    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_returns_bytes(self):
        """Output should be bytes."""
        result = encrypt_file(self.temp_file.name, self.password)
        self.assertIsInstance(result, bytes)

    def test_output_structure(self):
        """Check salt + nonce + ciphertext lengths."""
        result = encrypt_file(self.temp_file.name, self.password)
        self.assertGreater(len(result), SALT_SIZE + NONCE_SIZE, "Ciphertext must exist")

        # Extract parts
        salt = result[:SALT_SIZE]
        nonce = result[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        ciphertext = result[SALT_SIZE + NONCE_SIZE:]

        self.assertEqual(len(salt), SALT_SIZE)
        self.assertEqual(len(nonce), NONCE_SIZE)
        self.assertGreater(len(ciphertext), 0)

    def test_encryption_is_reversible(self):
        """Verify ciphertext can be decrypted correctly."""
        result = encrypt_file(self.temp_file.name, self.password)
        salt = result[:SALT_SIZE]
        nonce = result[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        ciphertext = result[SALT_SIZE + NONCE_SIZE:]

        key = derive_key(self.password.encode(), salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        self.assertEqual(plaintext, self.plaintext)

    def test_different_output_each_time(self):
        """Each encryption should produce different output due to random salt/nonce."""
        result1 = encrypt_file(self.temp_file.name, self.password)
        result2 = encrypt_file(self.temp_file.name, self.password)
        self.assertNotEqual(result1, result2, "Encryption should be non-deterministic")

    def test_encrypt_nonexistent_file(self):
        """Encrypting a non-existent file should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            encrypt_file("nonexistent.txt", self.password)

    def test_empty_file(self):
        """Encrypting an empty file should raise ValueError."""
        with tempfile.NamedTemporaryFile(delete=False) as empty_file:
            empty_file_path = empty_file.name
        try:
            with self.assertRaises(ValueError):
                encrypt_file(empty_file_path, self.password)
        finally:
            os.remove(empty_file_path)

    def test_invalid_password_type(self):
        """Should raise AttributeError if password is not a string."""
        with self.assertRaises(AttributeError):
            encrypt_file(self.temp_file.name, None)

    def test_password_empty_string(self):
        """Even empty password should still produce valid encryption (though insecure)."""
        result = encrypt_file(self.temp_file.name, "")
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), SALT_SIZE + NONCE_SIZE)

class TestDecryptFile(unittest.TestCase):

    def setUp(self):
        self.password = "strongpassword"
        self.wrong_password = "badpassword"
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()
        self.plaintext = b"Sensitive test data for AES-GCM"
        self.encrypted_data = create_encrypted_file(self.plaintext, self.password, self.temp_file.name)

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    # --- Positive case ---
    def test_successful_decryption(self):
        result = decrypt_file(self.temp_file.name, self.password)
        self.assertEqual(result, self.plaintext)

    # --- Negative cases ---
    def test_wrong_password_raises(self):
        with self.assertRaises(IncorrectPasswordOrCorruptedFile):
            decrypt_file(self.temp_file.name, self.wrong_password)

    def test_corrupted_ciphertext_raises(self):
        data = bytearray(self.encrypted_data)
        data[-1] ^= 0x01  # Flip a bit
        Path(self.temp_file.name).write_bytes(data)
        with self.assertRaises(IncorrectPasswordOrCorruptedFile):
            decrypt_file(self.temp_file.name, self.password)

    def test_corrupted_salt_raises(self):
        data = bytearray(self.encrypted_data)
        data[0] ^= 0xFF  # Modify salt
        Path(self.temp_file.name).write_bytes(data)
        with self.assertRaises(IncorrectPasswordOrCorruptedFile):
            decrypt_file(self.temp_file.name, self.password)

    def test_invalid_file_format_too_short(self):
        Path(self.temp_file.name).write_bytes(b"shortdata")
        with self.assertRaises(ValueError):
            decrypt_file(self.temp_file.name, self.password)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            decrypt_file("does_not_exist.enc", self.password)

    def test_empty_file_raises(self):
        Path(self.temp_file.name).write_bytes(b"")
        with self.assertRaises(ValueError):
            decrypt_file(self.temp_file.name, self.password)

    def test_empty_password(self):
        """Even with an empty password, decryption should still succeed if it matches encryption."""
        temp_path = tempfile.NamedTemporaryFile(delete=False).name
        create_encrypted_file(self.plaintext, "", temp_path)
        result = decrypt_file(temp_path, "")
        self.assertEqual(result, self.plaintext)
        os.remove(temp_path)

    def test_password_wrong_type(self):
        """If password isn't a string, we expect an AttributeError (since .encode() fails)."""
        with self.assertRaises(AttributeError):
            decrypt_file(self.temp_file.name, None)

    def test_file_with_extra_bytes_still_valid(self):
        """Extra trailing bytes should make AES-GCM fail authentication."""
        data = self.encrypted_data + b"EXTRA"
        Path(self.temp_file.name).write_bytes(data)
        with self.assertRaises(IncorrectPasswordOrCorruptedFile):
            decrypt_file(self.temp_file.name, self.password)


class TestSlotDiscovery(unittest.TestCase):
    def setUp(self):
        # Ensure a clean test environment
        if os.path.exists(INVOKER_HOME_DIR):
            shutil.rmtree(INVOKER_HOME_DIR)
        os.makedirs(INVOKER_SLOTS_DIR, exist_ok=True)

    def tearDown(self):
        # Clean up after each test
        if os.path.exists(INVOKER_HOME_DIR):
            shutil.rmtree(INVOKER_HOME_DIR)

    def create_slot_file(self, name, content=""):
        """Helper to create a slot file in slots directory."""
        path = Path(INVOKER_SLOTS_DIR) / name
        path.write_text(content)
        return path

    def test_find_slot_by_name(self):
        """Should find a slot by its exact name"""
        self.create_slot_file("slot1.py")
        self.create_slot_file("slot2.py")
        self.create_slot_file("slot3.py")

        results = find_slots("slot1")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].name.startswith("slot1"))

    def test_find_slot_by_name_not_found(self):
        """Should return empty list if slot name does not exist"""
        self.create_slot_file("slot1.py")
        self.create_slot_file("slot2.py")
        self.create_slot_file("slot3.py")

        results = find_slots("unsearchable_slot")
        self.assertEqual(results, [])

    def test_find_slot_by_name_enc(self):
        """Should find a slot by name when file has .enc suffix"""
        self.create_slot_file("slot1.enc")
        self.create_slot_file("slot2.enc")
        self.create_slot_file("slot3.enc")

        results = find_slots("slot2")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].name.startswith("slot2"))

    def test_find_slot_by_hash(self):
        """Should find a slot by its full hash"""
        file_path = self.create_slot_file("slot1.py", content="# Some comment")
        self.create_slot_file("slot2.enc")
        self.create_slot_file("slot3.py")

        sum_id = sha256sum(str(file_path))
        results = find_slots(sum_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].hash, sum_id)

    def test_find_slots_by_hash_prefix(self):
        """Should find slots that match the hash prefix"""
        file1 = self.create_slot_file("slot1.py", content="hello")
        file2 = self.create_slot_file("slot2.py", content="hello world")
        file3 = self.create_slot_file("slot3.py", content="hello universe")

        prefix = sha256sum(str(file1))[:6]
        results = find_slots(prefix)
        self.assertTrue(len(results) >= 1)
        self.assertIn(prefix, [slot.hash[:6] for slot in results])

    def test_find_slots_with_duplicate_hashes(self):
        """Should find multiple slots if they have identical hashes"""
        content = "same content"
        file1 = self.create_slot_file("slot1.py", content=content)
        file2 = self.create_slot_file("slot2.py", content=content)

        sum_id = sha256sum(str(file1))
        results = find_slots(sum_id)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(slot.hash == sum_id for slot in results))