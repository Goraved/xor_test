import itertools
import string
from itertools import cycle
from typing import List


class XorCipher:
    @staticmethod
    def xor_encrypt(text: str, key: str) -> str:
        """Encypt text value from 'abcde' to '\x18\x18\x1a\x1e\x1c'."""
        return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(text, cycle(key)))

    @staticmethod
    def xor_decrypt(encrypted_text: List[int], key: str) -> str:
        """Decrypt value from '[24, 24, 26, 30, 28]' to 'abcde'."""
        data = [chr(n) for n in encrypted_text]
        return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(data, cycle(key)))

    def guess_key(self, encrypted_text: List[int], key_len: int) -> dict:
        """Brute force decrypter to guess key by key_len only"""
        letters = list(string.ascii_lowercase)
        combinations = itertools.combinations_with_replacement(letters,
                                                               key_len)

        results = {}
        for xor_key in combinations:
            xor_key = "".join(xor_key)
            decoded = self.xor_decrypt(encrypted_text, xor_key)
            if decoded.isprintable():
                results[xor_key] = decoded

        return results
