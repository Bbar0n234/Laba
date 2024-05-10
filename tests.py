from main import text_to_binary, binary_to_text, khafre_cipher, khafre_decipher

from unittest import TestCase

import random


class MyTestCase(TestCase):
    def test_text_to_binary(self):
        self.assertEqual(text_to_binary("3234"), "00110011001100100011001100110100")

    def test_binary_to_text(self):
        self.assertEqual(binary_to_text("00110011001100100011001100110100"), "3234")

    def test_text_to_text(self):
        random_str = str(random.randint(1, 1000))
        self.assertEqual(random_str, binary_to_text(text_to_binary(random_str)))

    def test_khafre(self):
        test_str = "Hello_I_am_Ilya_3234k"
        test_key = "cryptokey"
        test_rounds = 8

        enc_str = khafre_cipher(test_str, test_key, test_rounds)
        dec_str = khafre_decipher(enc_str, test_key, test_rounds)

        self.assertEqual(test_str, dec_str)
