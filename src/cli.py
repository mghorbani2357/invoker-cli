import argparse
import ctypes
import getpass
import subprocess
import sys
import traceback

from invoker import *

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


class PasswordConfirmation(Exception):
    pass


def get_password(confirmation=False) -> str:
    password = getpass.getpass('Enter passphrase: ', stream=None)
    if confirmation:
        password_confirm = getpass.getpass('Please enter passphrase to confirm: ',
                                           stream=None)
        if password != password_confirm:
            raise PasswordConfirmation(f"Passphrase confirmation failed")

    return password


def create_parser():
    parser = argparse.ArgumentParser(description='Invoker CLI')
    parser.add_argument('-v', '--version', action='store_true', default=False, help='print tools version')

    subparsers = parser.add_subparsers(help='sub-command help')

    add_subparsers = subparsers.add_parser('add', help='add executable context into slots')
    add_subparsers.set_defaults(which='add')
    add_subparsers.add_argument('path', metavar='', type=str, help='path to python executable file')
    add_subparsers.add_argument('-e', '--encrypt', action='store_true', default=False, help='encrypt context')
    add_subparsers.add_argument('-l', '--load', action='store_true', default=False, help='load context')

    list_subparsers = subparsers.add_parser('list', help='list key smiths')
    list_subparsers.set_defaults(which='list')

    delete_subparsers = subparsers.add_parser('delete', help='add key from keyring')
    delete_subparsers.set_defaults(which='delete')
    delete_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')

    invoke_subparsers = subparsers.add_parser('invoke', help='invoke key from a file')
    invoke_subparsers.set_defaults(which='invoke')
    invoke_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')
    invoke_subparsers.add_argument('-f', '--path', metavar='', type=str, help='key path')

    save_subparsers = subparsers.add_parser('save', help='save key from keyring')
    save_subparsers.set_defaults(which='save')
    save_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')
    save_subparsers.add_argument('path', metavar='', type=str, help='path to where key should be saved')
    save_subparsers.add_argument('-d', '--decrypt', action='store_true', default=False, help='decrypt context')

    return parser


def main(args, parser):
    os.makedirs(INVOKER_HOME_DIR, exist_ok=True)
    os.makedirs(INVOKER_SLOTS_DIR, exist_ok=True)

    if hasattr(args, 'which'):
        match args.which:
            case 'add':
                try:
                    out_put_slot_path = ''
                    if args.load:
                        password = getpass.getpass('Enter passphrase to decrypt the module: ', stream=None)
                        out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{os.path.basename(args.path)}'
                        if validate_encrypted_module(args.path, password):
                            shutil.copy(args.path, out_put_slot_path)
                    else:
                        if validate_module(args.path):
                            password = get_password(True) if args.encrypt else None
                            if args.encrypt:
                                name, extension = os.path.splitext(os.path.basename(args.path))
                                out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{name}.enc{extension}'

                            add_slot(args.path, password)
                    if out_put_slot_path != '':
                        print(f"{sha256sum(out_put_slot_path)} added to slot-ring")

                except (InvalidModule, FileNotFoundError, InvalidSlotID, DuplicateSlotID, PasswordConfirmation) as e:
                    print(f"Operation aborted: {str(e)}", file=sys.stderr)
                    exit(1)

            case 'list':
                print("Key Hash    Key Name")
                print("--------    --------")
                print()

                slot_list = list_slots()
                for slot in slot_list:
                    print(f'{slot.hash[:8]}    {slot.name}')

            case 'delete':
                try:
                    delete_slot(args.id)
                    print(f"Slot `{args.id}` deleted")
                except (DuplicateSlotID, InvalidSlotID) as e:
                    print(str(e), file=sys.stderr)

            case 'invoke':
                clear_cli()
                try:
                    try:
                        candidate_slots = find_slots(args.id)
                        mssrio(candidate_slots)
                        slot_path = candidate_slots[0].path

                        password = None
                        if str(slot_path).endswith('.enc.py'):
                            password = getpass.getpass('Enter passphrase to decrypt the module:', stream=None)

                        invoke_slot(slot_path, password)

                    except (DuplicateSlotID, IncorrectPasswordOrCorruptedFile, InvalidSlotID) as e:
                        print(str(e), file=sys.stderr)
                except KeyboardInterrupt:
                    wipe_out()
                    return
                except:
                    print(traceback.print_exc())
                finally:
                    try:
                        getpass.getpass('Press `Enter` to wipe out', stream=None)
                    except KeyboardInterrupt:
                        wipe_out()
                    except:
                        pass
                    wipe_out()

                wipe_out()
            case 'save':
                try:
                    candidate_slots = find_slots(args.id)
                    mssrio(candidate_slots)
                    slot_path = candidate_slots[0].path
                    password = None
                    if args.decrypt and str(slot_path).endswith('.enc.py'):
                        password = getpass.getpass('Enter passphrase to decrypt the module:', stream=None)

                    save_slot(slot_path, args.path, password)
                    print(f"Slot `{args.id}` saved to `{args.path}`")

                except (InvalidSlotID, DuplicateSlotID, IncorrectPasswordOrCorruptedFile) as e:
                    print(str(e), file=sys.stderr)
                    exit(1)
            case _:
                parser.print_help()
    else:
        if args.version:
            print(f'Invoker-CLI(v{get_version()})')
        else:
            parser.print_help()


def cli():
    parser = create_parser()
    args = parser.parse_args()
    main(args, parser)


if __name__ == '__main__':
    cli()
