import argparse
import ast
import getpass
import importlib.util
import shutil
import traceback
import types

from invoker import *


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
                if os.path.exists(args.path):
                    if args.load:
                        try:
                            password = getpass.getpass('Enter passphrase to decrypt the module: ', stream=None)
                            context = decrypt_file(str(args.path), password)
                            ast.parse(context)
                            module_name = "module"
                            module = types.ModuleType(module_name)
                            namespace = module.__dict__
                            exec(context, namespace)
                            if hasattr(module, 'invoke'):
                                out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{os.path.basename(args.path)}'
                                shutil.copy(args.path, out_put_slot_path)
                                print(f"{sha256sum(out_put_slot_path)} added to slot-ring")

                            else:
                                print(f"Operation aborted: module does not have `invoke` method", file=sys.stderr)
                        except Exception:
                            print(f"Operation aborted: invalid context", file=sys.stderr)
                    else:

                        spec = importlib.util.spec_from_file_location('key', args.path)
                        module = importlib.util.module_from_spec(spec)
                        if spec.loader:
                            try:
                                spec.loader.exec_module(module)
                            except SyntaxError:
                                print(f"Operation aborted: invalid input", file=sys.stderr)
                                exit(1)
                            if hasattr(module, 'invoke'):
                                if args.encrypt:
                                    name, extension = os.path.splitext(os.path.basename(args.path))

                                    password = getpass.getpass('Enter passphrase to encrypt the module: ', stream=None)
                                    password_confirm = getpass.getpass('Please enter passphrase to confirm: ',
                                                                       stream=None)
                                    if password != password_confirm:
                                        print(f"Operation aborted: passphrase confirmation failed", file=sys.stderr)
                                        exit(1)
                                    buffer = encrypt_file(args.path, password)
                                    out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{name}.enc{extension}'
                                else:
                                    out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{os.path.basename(args.path)}'

                                    with open(args.path, 'rb') as f_in:
                                        buffer = f_in.read()
                                if find_slot(hashlib.sha256(buffer).hexdigest()) is None:
                                    with open(out_put_slot_path, 'wb') as f_out:
                                        f_out.write(buffer)
                                    print(f"{sha256sum(out_put_slot_path)} added to slot-ring")
                                else:
                                    print(f"Operation aborted: slot already exists", file=sys.stderr)
                            else:
                                print(f"Operation aborted: module does not have `invoke` method", file=sys.stderr)
                        else:
                            print(f"Operation aborted: No loader found for {args.path}", file=sys.stderr)
                else:
                    print(f"Operation aborted: file '{args.path}' does not exists", file=sys.stderr)

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
                        slot_path = find_slot(args.id)
                        password = None
                        if str(slot_path).endswith('.enc'):
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
                    slot_path = find_slot(args.id)
                    password = None
                    if args.decrypt and str(slot_path).endswith('.enc'):
                        password = getpass.getpass('Enter passphrase to decrypt the module:', stream=None)

                    save_slot(slot_path, args.path, password)
                    print(f"Slot `{args.id}` saved to `{args.path}`")

                except (InvalidSlotID ,DuplicateSlotID, IncorrectPasswordOrCorruptedFile) as e:
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
