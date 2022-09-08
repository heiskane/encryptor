#!/usr/bin/env python
"""File encryptor"""
import os
import sys
import hashlib
from io import BufferedReader
from dataclasses import dataclass
from argparse import ArgumentParser, Namespace, FileType
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# Ugly as hell but created only to get a better
# understanding of CBC mode for AES


class EncyptionManager:
    """Encryption manager class

    Attributes:
        key: A SHA256 hash of the password
    """

    def __init__(self, key: str) -> None:
        """
        Initialize Encryption manager

        Args:
            key: String that acts as a password
        """
        self._init_vector = os.urandom(16)
        # Use sha256 hash of the "password" as the key
        self.key = hashlib.sha256(key.encode()).digest()
        self._aes_context = Cipher(
            algorithms.AES(self.key), modes.ECB(), backend=default_backend()
        )
        self._encryptor = self._aes_context.encryptor()
        self._decryptor = self._aes_context.decryptor()
        self._padder = padding.PKCS7(128).padder()
        self._unpadder = padding.PKCS7(128).unpadder()

    def update_encryptor(self, plaintext: bytes) -> bytes:
        """update encryptor"""
        return self._encryptor.update(plaintext)

    def finalize_encryptor(self) -> bytes:
        """finalize encryptor"""
        return self._encryptor.finalize()

    def update_decryptor(self, ciphertext: bytes) -> bytes:
        """update decryptor"""
        return self._decryptor.update(ciphertext)

    def finalize_decryptor(self) -> bytes:
        """finalize decryptor"""
        return self._decryptor.finalize()

    def xor_bytes(self, input1: bytes, input2: bytes) -> bytes:
        """XOR two inputs"""
        output = b""
        for i, j in zip(input1, input2):
            output += bytes([i ^ j])
        return output
        # Could use a oneliner
        # return b"".join([bytes([i ^ j]) for i, j in zip(input1, input2)])

    def encrypt(self, message: bytes) -> bytes:
        """Encrypt message using CBC mode"""
        msg = self._padder.update(message)
        msg += self._padder.finalize()

        xored = self.xor_bytes(msg[:16], self._init_vector)
        encrypted = self.update_encryptor(xored)

        for i in range(16, len(msg), 16):
            xored = self.xor_bytes(msg[i : i + 16], encrypted[i - 16 : i])
            encrypted += self.update_encryptor(xored)

        encrypted += self.finalize_encryptor()
        # Add the IV to the encrypted data
        return self._init_vector + encrypted

    def decrypt(self, msg: bytes) -> bytes:
        """Decrypt message using CBC mode"""
        # Get the IV (First 16 bytes)
        init_vector = msg[:16]

        # Cut the IV out
        msg = msg[16:]
        decrypted = self.update_decryptor(msg[:16])
        xored = self.xor_bytes(decrypted, init_vector)

        for i in range(16, len(msg), 16):
            block = self.update_decryptor(msg[i : i + 16])
            xored += self.xor_bytes(msg[i - 16 : i], block)

        unpadded = self._unpadder.update(xored)
        unpadded += self._unpadder.finalize()
        return unpadded


# https://www.programcreek.com/python/example/5080/argparse.FileType
def parse() -> Namespace:
    """Parse commandline arguments"""
    parser = ArgumentParser(description="Encrypt a file with AES-CBC")

    parser.add_argument(
        "-d", "--decrypt", action="store_true", default=False, help="Decrypt the file"
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="in_file",
        type=FileType("rb"),
        default=sys.stdin.buffer,
        help="Choose an input file (Default: stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="out_file",
        type=FileType("wb"),
        default=sys.stdout.buffer,
        help="Choose an outfile (Default: stdout)",
    )

    required = parser.add_argument_group("Required arguments")

    required.add_argument(
        "-k",
        "--key",
        type=str,
        required=True,
        help="The key for encryption and decryption",
    )

    return parser.parse_args()


@dataclass
class Arguments:
    """A dataclass to represent arguments"""

    in_file: BufferedReader
    out_file: BufferedReader
    key: str
    decrypt: bool = False


def main() -> None:
    """Entrypoint or whaterver"""
    args = Arguments(**vars(parse()))
    manager = EncyptionManager(args.key)
    message = args.in_file.read()

    if args.decrypt:
        output = manager.decrypt(message)
    else:
        output = manager.encrypt(message)

    args.out_file.write(output)


if __name__ == "__main__":
    main()
