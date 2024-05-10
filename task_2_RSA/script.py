#!/usr/bin/env -S python
# -*- coding:utf-8 -*-

import random

from tqdm import tqdm

import itertools
import string
import time

N = 24671716616329429791501934120401986947906754762069027741103489695301393684913192968714393770506588974171119688004078255560092540876759761037785737486298735119250686595158517199167275161581367984820060098272828867789598314992199539669137605464550007399992348571
enc = 8708668393469727278778838158627673326859139312038572460295304871851740864405543976926208190311440529132718385828240461582019852900615915862789624823351491282779122037086425344420295176523983133369992810358802699128572770491607029762924369849408692830226944146


# Преобразуем строку в число
def string_to_int(s):
    res = 0
    for c in s:
        res = res * 256 + ord(c)
    return res


# Преобразуем число в строку
def int_to_string(n):
    res = ""
    while n > 0:
        res += chr(n % 256)
        n //= 256
    return res[::-1]


# Тест Миллера—Рабина на простоту числа
def is_prime(n, num_of_iter=10):
    if n % 2 == 0:
        return False
    t = n - 1
    s = 0
    while t % 2 == 0:
        t //= 2
        s += 1
    for _ in range(num_of_iter):
        a = random.randint(2, n - 1)
        if pow(a, t, n) == 1:
            continue
        i = 0
        while i < s:
            if pow(a, 2 ** i * t, n) == n - 1:
                break
            i += 1
        if i == s:
            return False
    return True


# Генерация 2х простых чисел
def gen_primes(nbit=80):
    while True:
        k = random.getrandbits(nbit)
        p = k ** 6 + 7 * k ** 4 - 40 * k ** 3 + 12 * k ** 2 - 114 * k + 31377
        q = k ** 5 - 8 * k ** 4 + 19 * k ** 3 - 312 * k ** 2 - 14 * k + 14011
        if is_prime(p) and is_prime(q):
            return p, q


# Шифрование RSA
def encrypt(msg, n, e=65537):
    return pow(msg, e, n)


# p, q = gen_primes()
# n = p * q
#
# inf = open("flag.txt", "rt")
# flag = inf.read()
# flag = string_to_int(flag)
# inf.close()
#
# enc = encrypt(flag, n)
#
# outf = open("output.txt", "wt")
# res = "N = " + str(n) + "\nenc = " + str(enc)
# outf.write(res)
# outf.close()

start_value = 351119173421513132134800

k = 381161505336546621355963

p = k ** 6 + 7 * k ** 4 - 40 * k ** 3 + 12 * k ** 2 - 114 * k + 31377
q = k ** 5 - 8 * k ** 4 + 19 * k ** 3 - 312 * k ** 2 - 14 * k + 14011

p = 3066579306771115597687355686076076758022522055618718889724892460135650967004290207979084075958166724079946365284607200141677587668800511275679
q = 8045354170966133722859905033223225612067486934384038000035996890974945627950634715342603756391574516419577772753935749
e = 65537


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def calculate_d(p, q, e):
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return d


d = calculate_d(p, q, e)


def decrypt_message(ciphertext, d, p, q):
    n = p * q
    decrypted_message = pow(ciphertext, d, n)
    return decrypted_message


decrypted_message = decrypt_message(enc, d, p, q)

print(int_to_string(decrypted_message))
