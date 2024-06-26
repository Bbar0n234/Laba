'''Модуль для написания Юнит-тестов'''
from unittest import TestCase
from main import text_to_binary, binary_to_text, khafre_cipher, khafre_decipher


class MyTestCase(TestCase):
    """Класс для Юнит-тестов"""
    def test_text_to_binary(self):
        """
        :return: fndsnjklfknsdknsdf
        """
        self.assertEqual(text_to_binary("3234"), "00110011001100100011001100110100")

    def test_binary_to_text(self):
        """
        :param a: 1234123
        :param b: 1234123
        :return: 1234123 1234123
        """
        self.assertEqual(binary_to_text("00110011001100100011001100110100"), "3234")

    def test_text_to_text(self):
        """
        :return:
        """
        test_str = "3234"
        self.assertEqual(test_str, binary_to_text(text_to_binary(test_str)))

    def test_khafre(self):
        """
        :return:
        """
        test_str = "Hello_I_am_Ilya_3234k"
        test_key = "cryptokey"
        test_rounds = 8

        enc_str = khafre_cipher(test_str, test_key, test_rounds)
        dec_str = khafre_decipher(enc_str, test_key, test_rounds)

        self.assertEqual(test_str, dec_str)
