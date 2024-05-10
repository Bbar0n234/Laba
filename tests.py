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
        random_str = str(random.randint(1, 1000))
        random_key = str(random.randint(1000, 100000))
        random_rounds = random.randint(8, 16)

        enc_str = khafre_cipher(random_str, random_key, random_rounds)
        dec_str = khafre_decipher(enc_str, random_key, random_rounds)

        self.assertEqual(random_str, dec_str)