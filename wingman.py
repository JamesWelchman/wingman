#!/usr/bin/env python

import hmac
from os import environ, mkdir, urandom
from sys import argv, stdin, stderr, exit
from pathlib import Path
from functools import partial
from hashlib import sha256
from struct import pack

eprint = partial(print, file=stderr)

# We depend on argon2 for safe hashing
# We also need AES
try:
    from argon2 import argon2_hash
    from Crypto.Cipher import AES
except ImportError as exc:
    eprint("couldn't find cryto libraries - {!s}", exc)


VERSION = b"\x00"


class WingmanException(Exception):
    pass


class InvalidUserKey(WingmanException, ValueError):
    pass


class InvalidArgument(WingmanException):
    pass


class UnrecognisedVersion(WingmanException):
    pass


class InvalidFileHash(WingmanException, ValueError):
    pass


class AmbiguousFileHash(WingmanException):
    pass


def encrypt(enc_key, file_data):
    # Compute the padding length
    # Make the file_data a multiple of 32 bytes
    # long.
    pad_length = 32 - (len(file_data) % 32)
    file_data = urandom(pad_length) + file_data

    meta_data = VERSION + pack("B", pad_length) + urandom(14)
    key = urandom(32)
    iv = urandom(16)

    # Encrypt the header
    aes = AES.new(enc_key, AES.MODE_ECB)
    enc_header = meta_data + aes.encrypt(key + iv)

    # Okay - encyrpt the data
    aes = AES.new(key, AES.MODE_CBC, iv)
    enc_data = aes.encrypt(file_data)

    return enc_header + enc_data


def decrypt(enc_key, enc_data):
    meta_data = enc_data[:16]
    if meta_data[0:1] != VERSION:
        err_str = "unsupported version {!s}".format(VERSION)
        raise UnrecognisedVersion(err_str)
    pad_length = meta_data[1]

    # Grab the key + iv
    enc_keys = enc_data[16:64]
    aes = AES.new(enc_key, AES.MODE_ECB)
    keys = aes.decrypt(enc_keys)
    key, iv = keys[:32], keys[32:48]

    # Decrypt the data
    aes = AES.new(key, AES.MODE_CBC, iv)
    data = aes.decrypt(enc_data[64:])

    # return the decrypted data with the padding
    # stripped.
    return data[pad_length:]


def cmd_ls(enc_dir, *args):
    # Call the ls implementation
    def is_encfile(fname):
        if len(fname) != 64:
            return False
        for c in fname.lower():
            if c not in "abcdef0123456789":
                return False

        return True

    iterator = map(lambda x: x.name, enc_dir.glob('*'))
    return "\n".join(filter(is_encfile, iterator))


def cmd_add(user_key, enc_dir, *args):
    # Args should be of length 1
    # The file which we wish to encrypt
    if len(args) != 1 or not isinstance(args[0], str):
        err_str = "add command requires one argument, a str filepath"
        raise InvalidArgument(err_str)

    # We support the magic values '-' and '-0' for stdin
    if args[0] == '-' or args[0] == '-0':
        file_data = stdin.buffer.read()
    else:
        file = Path(args[0]).expanduser().absolute()
        assert file.exists(), "{!s} does not exist".format(file)
        file_data = open(file, 'rb').read()

    # Okay - read the salt
    salt = open(enc_dir / "salt", 'rb').read()

    # Generate the hash
    ahash = argon2_hash(user_key, salt)

    # enc_key is used to encrypt the file header
    enc_key = ahash[:32]
    # file_salt to used to salt the hashes
    file_salt = ahash[32:64]

    # Encrypt the data
    enc_data = encrypt(enc_key, file_data)

    # Generate the file_hash
    file_hash = hmac.new(
        key=file_salt,
        msg=file_data,
        digestmod=sha256,
    ).digest().hex()

    with open(enc_dir / file_hash, 'wb') as file:
        file.write(enc_data)

    return file_hash


def cmd_cat(user_key, enc_dir, *args):
    # Args should be of length 1
    # and should be a lowercase hexstring
    if len(args) != 1 or not isinstance(args[0], str):
        err_str = "cat command requires one argument, a str hexstring"
        raise InvalidArgument(err_str)

    if len(args[0]) < 6 or len(args[0]) > 64:
        err_str = "cat command requires unique id between 6 and 64 chars"
        raise InvalidArgument(err_str)

    # Grab the filenames
    filenames = cmd_ls(enc_dir).split("\n")

    # How many filenames start with args[0]?
    filenames = list(
        filter(lambda x: x.startswith(args[0]), filenames)
    )

    if len(filenames) == 0:
        err_str = "{!s} does not exist"
        raise InvalidFileHash(err_str)
    elif len(filenames) >= 2:
        err_str = "ambiguous file hash"
        raise AmbiguousFileHash(err_str)

    # Read the file
    filename = filenames[0]
    enc_data = open(enc_dir / filename, 'rb').read()

    # Okay - read the salt
    salt = open(enc_dir / "salt", 'rb').read()

    # Generate the hash
    ahash = argon2_hash(user_key, salt)

    # enc_key is used to encrypt the file header
    enc_key = ahash[:32]

    # Decrypt the data
    return decrypt(enc_key, enc_data)


def validate_user_key(user_key):
    """
    validate_user_key checks the key is a hexstring
    of length 64 (or 32 bytes).
    """
    if not isinstance(user_key, str):
        raise TypeError("user_key should be a str")

    err_str = "user_key must be a hexstring of length 64"

    if len(user_key) != 64:
        raise InvalidUserKey(err_str)

    for c in user_key.lower():
        if c not in "abcdef0123456789":
            raise InvalidUserKey(err_str)


def output(out):
    """
    output prints the output to stdout.
    """

    if not out:
        # Don't bother if out is empty
        return

    # Attempt to UTF-8 decode - assuming
    # the data is text. This displays newlines
    # correctly.
    if isinstance(out, (bytes, bytearray)):
        try:
            out = str(out, encoding='utf8')
        except UnicodeDecodeError:
            pass

    end = ""
    if isinstance(out, str) and out[-1] != "\n":
        end = "\n"

    print(out, end=end)


def wingman(user_key, enc_dir, cmd, *args):
    # Sanity check the user_key
    validate_user_key(user_key)
    user_key = bytes.fromhex(user_key)

    # Check + create the enc_dir
    enc_dir = Path(enc_dir).expanduser().absolute()
    if not enc_dir.exists():
        mkdir(enc_dir)

    if not (enc_dir / "salt").exists():
        with open(enc_dir / "salt", 'wb') as file:
            file.write(urandom(32))
    else:
        # TODO: Sanity check the salt
        pass

    # Now we need to switch on the cmd
    try:
        if cmd == "ls":
            output(cmd_ls(enc_dir, *args))
        elif cmd == "add":
            output(cmd_add(user_key, enc_dir, *args))
        elif cmd == "cat":
            output(cmd_cat(user_key, enc_dir, *args))
    except WingmanException as exc:
        # TODO: How to handle this error?
        eprint("invalid argument - {!s}".format(exc))


if __name__ == '__main__':
    # Grab the key
    user_key = environ.get("WINGMAN_USER_KEY")
    if not user_key:
        eprint("WINGMAN_USER_KEY environment variable not set")
        exit(1)

    # Grab the directory
    enc_dir = environ.get("WINGMAN_ENC_DIR", "/tmp/wingman")

    if len(argv) < 2:
        eprint("argument required - try -h for help")
        exit(1)

    try:
        wingman(user_key, enc_dir, argv[1], *argv[2:])
    except Exception as exc:
        # Something went wrong
        eprint("something went wrong - {!s}".format(exc))
        exit(1)


__all__ = ['wingman']
