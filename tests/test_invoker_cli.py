import io
import os.path
import shutil
import unittest
from contextlib import redirect_stdout, redirect_stderr, suppress
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, mock_open

import src.invoker as invoker_module
from src.invoker import create_parser, main

SCRIPTS_PATH = 'tests/_helper/scripts'
LOCK_FILE_PATH = "/tmp/invoker.lock"

def initialize_test_environment():
    if os.path.exists(invoker_module.INVOKER_HOME_DIR):
        os.rename(
            invoker_module.INVOKER_HOME_DIR,
            f"{invoker_module.INVOKER_HOME_DIR}.backup"
        )
    os.mkdir(invoker_module.INVOKER_HOME_DIR)
    os.mkdir(invoker_module.INVOKER_SLOTS_DIR)


def wipe_out_test_environment():
    shutil.rmtree(invoker_module.INVOKER_HOME_DIR, )
    if os.path.exists(f"{invoker_module.INVOKER_HOME_DIR}.backup"):
        os.rename(
            f"{invoker_module.INVOKER_HOME_DIR}.backup",
            invoker_module.INVOKER_HOME_DIR
        )


class BaseInvokerCLITestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_test_environment()

    @classmethod
    def tearDownClass(cls):
        wipe_out_test_environment()

    @staticmethod
    def clean_up():
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR, )
        os.mkdir(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_SLOTS_DIR)

    def setUp(self):
        self.clean_up()

    def tearDown(self):
        self.clean_up()


class TestMainModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_bare_input(self):
        parser = create_parser()
        args = parser.parse_args([])
        f = io.StringIO()
        with redirect_stdout(f):
            main(args, parser)
        output = f.getvalue().strip()

    def test_version(self):
        parser = create_parser()
        args = parser.parse_args(['-v'])
        main(args, parser)


def execute_and_get_output(arguments: list, raise_system_exit_suppression=True):
    parser = create_parser()
    args = parser.parse_args(arguments)
    f = io.StringIO()
    e = io.StringIO()
    suppressed = True
    with suppress(SystemExit) as cm:
        with redirect_stdout(f):
            with redirect_stderr(e):
                main(args, parser)
                suppressed = False

    if suppressed and raise_system_exit_suppression:
        raise Exception('Invalid SystemExit occurred')

    return f, e


class TestAddModuleOfInvokerCLI(BaseInvokerCLITestCase):
    @patch('getpass.getpass', side_effect=[''])
    def test_add_bare_slot(self, mock_getpass):
        execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")
        self.assertTrue(bare_invoker_path.exists(), f"File does not exist: {bare_invoker_path.absolute()}")

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase'])
    def test_add_slot_with_encryption(self, mock_getpass):
        execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.enc.py")
        self.assertTrue(bare_invoker_path.exists(), f"File does not exist: {bare_invoker_path.absolute()}")
        self.assertNotEqual(
            invoker_module.sha256sum(bare_invoker_path.absolute()),
            invoker_module.sha256sum(f'{SCRIPTS_PATH}/bare_invoke.py'),
            "Hash of file after encryption doesn't changed"
        )

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase', 'VerySecurePassPhrase'])
    def test_add_import(self, mock_getpass):
        execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'])
        shutil.move(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.enc.py", '/tmp/invoke.enc.py')
        f,e = execute_and_get_output(['add', '/tmp/invoke.enc.py', '--load'])

        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/invoke.enc.py")
        self.assertTrue(bare_invoker_path.exists(), f"File does not exist: {bare_invoker_path.absolute()}")


    def test_add_empty_file(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/empty_file.py'])
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: module does not have `invoke` method", output)

    def test_add_incorrect_file(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/incorrect.py'], False)
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: invalid input", output)

    def test_add_py_file_without_invoke_method(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/without_invoke.py'])
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: module does not have `invoke` method", output)

    def test_add_so_file_without_invoke_method(self):
        pass

    def test_add_correct_py_file(self):
        execute_and_get_output(['add', f'{SCRIPTS_PATH}/correct.py'])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/correct.py")
        self.assertTrue(bare_invoker_path.exists(), f"File does not exist: {bare_invoker_path.absolute()}")

    def test_add_correct_so_file(self):
        pass

    def test_import_already_encrypted_file(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'], False)
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'], False)
        output = e.getvalue().strip()
        self.assertEqual(f"Operation aborted: slot already exists", output)

    def test_invalid_path(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/invalid_path.py'], False)
        output = e.getvalue().strip()
        self.assertEqual(f"Operation aborted: file '{SCRIPTS_PATH}/invalid_path.py' does not exists", output)

    @patch('getpass.getpass', side_effect=['SomePassPhrase', 'DifferentPassPhrase'])
    def test_password_confirmation(self, mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'], False)
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: passphrase confirmation failed", output)

    def test_add_duplilcate_file_names(self):
        pass
class TestListModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_list_before_any_addition(self):
        f, e = execute_and_get_output(['list'])
        self.assertEqual("Key Hash    Key Name\n--------    --------", f.getvalue().strip())

    def test_list_after_single_slot_addition(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'], False)
        f, e = execute_and_get_output(['list'])
        output = f.getvalue().strip()
        self.assertEqual("Key Hash    Key Name\n--------    --------\n\n07dc3eb2    bare_invoke", output)

    # def test_list_after_multiple_slots_addition(self):
    #     f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'], False)
    #     f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/correct.py'], False)
    #     f, e = execute_and_get_output(['list'])
    #     output = f.getvalue().strip()
    #     self.assertEqual("Key Hash    Key Name\n--------    --------\n\n07dc3eb2    bare_invoke\n344fa8c3    correct", output)

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase'])
    def test_list_after_encrypted_slot_addition(self, mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'], False)
        f, e = execute_and_get_output(['list'])
        output = f.getvalue().strip()
        slot_sha256 = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.enc.py")[:8]
        self.assertEqual(f"Key Hash    Key Name\n--------    --------\n\n{slot_sha256}    bare_invoke.enc", output)


class TestDeleteModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_delete_slot_by_name(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'], False)
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/correct.py'], False)
        f, e = execute_and_get_output(['delete', 'bare_invoke'])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")
        self.assertFalse(bare_invoker_path.exists(), f"File exist: {bare_invoker_path.absolute()}")

    def test_delete_slot_by_id(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'])
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/correct.py'])
        slot_sha256 = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")[:8]

        f, e = execute_and_get_output(['delete', slot_sha256])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")
        self.assertFalse(bare_invoker_path.exists(), f"File exist: {bare_invoker_path.absolute()}")

    def test_delete_duplicate_slots_by_sha256(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'])
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/correct.py'])
        shutil.copy(f'{SCRIPTS_PATH}/bare_invoke.py', f'{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke_copy.py')

        slot_sha256 = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")[:8]

        f, e = execute_and_get_output(['delete', slot_sha256])
        output = e.getvalue().strip()
        self.assertEqual(f"Error: Multiple identifiers found with provided prefix: {slot_sha256}", output)

    def test_delete_none_existing_slot(self):
        f, e = execute_and_get_output(['delete', 'not_existing_slot'])
        output = e.getvalue().strip()
        self.assertEqual(f"Unable to find the slot: not_existing_slot", output)


class TestSaveModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_save_slot_by_name(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'])
        tmp_saved_slot_path = '/tmp/saved_slot.py'
        f, e = execute_and_get_output(['save', 'bare_invoke', tmp_saved_slot_path])
        self.assertTrue(os.path.exists(tmp_saved_slot_path), "Unable to find saved slot")
        os.remove(tmp_saved_slot_path)
        self.assertTrue(f"Slot `bare_invoke` saved to `{tmp_saved_slot_path}`", f.getvalue().strip())

    def test_save_slot_by_id(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'])
        tmp_saved_slot_path = '/tmp/saved_slot.py'
        slot_sha256 = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")[:8]
        f, e = execute_and_get_output(['save', slot_sha256, tmp_saved_slot_path])
        self.assertTrue(os.path.exists(tmp_saved_slot_path), "Unable to find saved slot")
        os.remove(tmp_saved_slot_path)
        self.assertTrue(f"Slot `{slot_sha256}` saved to `{tmp_saved_slot_path}`", f.getvalue().strip())

    def test_save_duplicate_slots_by_id(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'])
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/correct.py'])
        tmp_saved_slot_path = '/tmp/saved_slot.py'
        shutil.copy(f'{SCRIPTS_PATH}/bare_invoke.py', f'{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke_copy.py')
        slot_sha256 = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")[:8]

        f, e = execute_and_get_output(['save', slot_sha256, tmp_saved_slot_path], False)

        output = e.getvalue().strip()
        self.assertEqual(f"Error: Multiple identifiers found with provided prefix: {slot_sha256}", output)

    def test_save_none_existing_slot(self):
        f, e = execute_and_get_output(['save', 'not_existing_slot', 'some_tmp_path'])
        output = e.getvalue().strip()
        self.assertEqual(f"Unable to find the slot: not_existing_slot", output)

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase', 'VerySecurePassPhrase'])
    def test_save_encrypted_slot(self, mock_getpass):
        tmp_saved_slot_path = '/tmp/saved_slot.py'

        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'], False)
        f, e = execute_and_get_output(['save', 'bare_invoke', tmp_saved_slot_path, '--decrypt'])

        self.assertTrue(os.path.exists(tmp_saved_slot_path), "Unable to find saved slot")
        self.assertTrue(f"Slot `bare_invoke` saved to `{tmp_saved_slot_path}`", f.getvalue().strip())

        os.remove(tmp_saved_slot_path)

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase', 'WrongPassPhrase'])
    def test_save_encrypted_slot_with_wrong_pass_phrase(self, mock_getpass):
        tmp_saved_slot_path = '/tmp/saved_slot.py'

        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'])
        f, e = execute_and_get_output(['save', 'bare_invoke', tmp_saved_slot_path, '--decrypt'], False)

        self.assertEqual(f"Decryption failed: incorrect password or corrupted file", e.getvalue().strip())

        os.remove(tmp_saved_slot_path)


class TestInvokerModuleOfInvokerCLI(BaseInvokerCLITestCase):
    # def test_invoker_from_external_file(self):
    #     pass
    #
    # def test_invoker_from_external_encrypted_file(self):
    #     pass
    #
    # def test_invoker_user_code_exception(self):
    #     pass

    @patch('getpass.getpass', return_value='')
    def test_invoker_by_id(self, mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/create_lock.py'])
        slot_sha256 = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/create_lock.py")[:8]
        f, e = execute_and_get_output(['invoke', slot_sha256])
        self.assertTrue(os.path.exists(LOCK_FILE_PATH), "Unable to find flag file")
        os.remove(LOCK_FILE_PATH)

    @patch('getpass.getpass', return_value='')
    def test_invoker_by_name(self, mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/create_lock.py'])
        f, e = execute_and_get_output(['invoke', 'create_lock'])
        self.assertTrue(os.path.exists(LOCK_FILE_PATH), "Unable to find flag file")
        os.remove(LOCK_FILE_PATH)

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase', 'VerySecurePassPhrase', ''])
    def test_invoker_by_id_encrypted_mode(self,mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/create_lock.py', '--encrypt'])
        f, e = execute_and_get_output(['invoke', 'create_lock'])
        self.assertTrue(os.path.exists(LOCK_FILE_PATH), "Unable to find flag file")
        os.remove(LOCK_FILE_PATH)

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase', 'VerySecurePassPhrase', ''])
    def test_invoker_by_name_encrypted_mode(self,mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/create_lock.py', '--encrypt'])
        slot_sha256 = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/create_lock.enc.py")[:8]
        f, e = execute_and_get_output(['invoke', slot_sha256])
        self.assertTrue(os.path.exists(LOCK_FILE_PATH), "Unable to find flag file")
        os.remove(LOCK_FILE_PATH)

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase', 'WrongPassPhrase', ''])
    def test_invoker_wrong_pass_phrase(self,mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/create_lock.py', '--encrypt'])
        f, e = execute_and_get_output(['invoke', 'create_lock'])
        self.assertEqual(f"Decryption failed: incorrect password or corrupted file", e.getvalue().strip())

    @patch('getpass.getpass', return_value='')
    def test_invoker_none_existing_slot(self, mock_getpass):
        f, e = execute_and_get_output(['invoke', 'not_existing_slot'], False)
        output = e.getvalue().strip()
        self.assertEqual(f"Unable to find the slot: not_existing_slot", output)

class TestSlotDiscovery(BaseInvokerCLITestCase):
    def test_search_by_name(self):
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()
        self.assertIsNotNone(invoker_module.find_slot('slot1'))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    def test_unable_to_find_slot(self):
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()
        self.assertIsNone(invoker_module.find_slot('unsearchable_slot'))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    def test_search_by_name_enc(self):
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.enc").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.enc").touch()
        self.assertIsNotNone(invoker_module.find_slot('slot2'))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    def test_search_by_id(self):
        with open(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py", 'w') as file:
            file.write("# Some comment to change the sha256sum")
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()

        sum_id = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py")
        self.assertIsNotNone(invoker_module.find_slot(sum_id))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    # def test_duplicate_id(self): Todo: why I add this?
    #     Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py").touch()
    #     Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc").touch()
    #     Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()
    #     sum_id = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc")
    #     self.assertIsNone(invoker_module.find_slot(sum_id))
    #     shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
    #     os.mkdir(invoker_module.INVOKER_HOME_DIR)


class TestEncryptionDecryptionModules(TestCase):
    def test_encrypt_decrypt_modules(self):
        pass_phrase = 'VerySecurePassPhrase'

        fake_content = b"some test content\nanother line"
        mc = mock_open(read_data=fake_content)
        with patch("builtins.open", mc):
            # Now call the function that expects a file path
            enc_result = invoker_module.encrypt_file(f'{SCRIPTS_PATH}/bare_invoke.py', pass_phrase)
        fake_cipher_content = enc_result
        md = mock_open(read_data=fake_cipher_content)
        with patch("builtins.open", md):
            # Now call the function that expects a file path
            dec_result = invoker_module.decrypt_file(f'{SCRIPTS_PATH}/bare_invoke.py', pass_phrase)
        self.assertEqual(fake_content, dec_result, "Plain content and deciphered content aren't equal")

    def test_decrypt_incorrect_password(self):
        pass_phrase = 'VerySecurePassPhrase'

        fake_content = b"some test content\nanother line"
        mc = mock_open(read_data=fake_content)
        with patch("builtins.open", mc):
            # Now call the function that expects a file path
            enc_result = invoker_module.encrypt_file(f'{SCRIPTS_PATH}/bare_invoke.py', pass_phrase)
        fake_cipher_content = enc_result
        md = mock_open(read_data=fake_cipher_content)
        with patch("builtins.open", md):
            # Now call the function that expects a file path
            with self.assertRaises(invoker_module.IncorrectPasswordOrCorruptedFile):
                dec_result = invoker_module.decrypt_file(f'{SCRIPTS_PATH}/bare_invoke.py', 'incorrect_password')


class TestCleanUpAndWipeOut(TestCase):
    @unittest.skipIf(os.name != 'nt', "Skip on non-Windows platforms")
    @patch("sys.stdout.write")
    @patch("sys.stdout.flush")
    def test_clean_up_cli_on_windows(self, mock_flush, mock_write):
        invoker_module.clear_cli()
        mock_write.assert_called_with('\x1b[?1049h')
        mock_flush.assert_called_once()

    @unittest.skipIf(os.name == 'nt', "Skip on Windows")
    @patch("subprocess.run")
    def test_clean_up_cli_on_nix_based_platform(self, mock_run):
        invoker_module.clear_cli()
        mock_run.assert_called_once_with('tput smcup', shell=True)

    @unittest.skipIf(os.name != 'nt', "Skip on non-Windows platforms")
    @patch("sys.stdout.write")
    @patch("sys.stdout.flush")
    def test_wipe_out_on_windows(self, mock_flush, mock_write):
        invoker_module.wipe_out()
        mock_write.assert_called_with('\x1b[?1049l')
        mock_flush.assert_called_once()

    @unittest.skipIf(os.name == 'nt', "Skip on Windows")
    @patch("subprocess.run")
    def test_wipe_out_on_nix_based_platform(self, mock_run):
        invoker_module.wipe_out()
        mock_run.assert_called_once_with('tput rmcup', shell=True)
