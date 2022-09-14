import pytest

from xor_cipher import XorCipher


class TestsXor:
    @property
    def xor(self) -> XorCipher:
        return XorCipher()

    @pytest.fixture()
    def decrypted(self):
        return self.xor.xor_decrypt([24, 24, 26, 30, 28], "yz")

    def test_decrypt(self):
        value = self.xor.xor_decrypt([24, 24, 26, 30, 28], "yz")

        assert value.isprintable()
        assert value == "abcde"

    @pytest.mark.parametrize(
        "key",
        ["y", "ac", "yza", "Yz", ""],
        ids=["short", "wrong", "long", "capitalize", "empty"],
    )
    def test_decrypt_wrong_key(self, key):
        value = self.xor.xor_decrypt([24, 24, 26, 30, 28], key)

        assert value != "abcde"

    def test_encrypt(self, decrypted):
        value = self.xor.xor_encrypt(decrypted, "yz")

        assert value == "\x18\x18\x1a\x1e\x1c"
        assert not value.isprintable()

    @pytest.mark.parametrize(
        "key",
        ["y", "ac", "yza", "Yz", ""],
        ids=["short", "wrong", "long", "capitalize", "empty"],
    )
    def test_encrypt_wrong_key(self, decrypted, key):
        value = self.xor.xor_encrypt(decrypted, key)

        assert value != "\x18\x18\x1a\x1e\x1c"

    def test_brute_force(self):
        results = self.xor.guess_key([24, 24, 26, 30, 28], 2)

        assert "yz" in results
        assert results["yz"] == "abcde"

    def test_brute_force_file(self):
        with open("cipher.txt") as f:
            file_data = f.read()
        file_values = [int(_) for _ in file_data.split(",")]

        possible_results = self.xor.guess_key(file_values, 3)

        # There are no readable text, but need to test that at least some readable data present
        assert possible_results
