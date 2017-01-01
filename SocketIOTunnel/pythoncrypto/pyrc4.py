#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>

from __future__ import absolute_import, division, print_function, \
    with_statement

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Pure-Python RC4 implementation."""


class RC4(object):
    def __init__(self, keyBytes):
        if len(keyBytes) < 16 or len(keyBytes) > 256:
            raise ValueError()
        S = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + S[i] + keyBytes[i % len(keyBytes)]) % 256
            S[i], S[j] = S[j], S[i]

        self.S = S
        self.i = 0
        self.j = 0

    def encrypt(self, plaintextBytes):
        ciphertextBytes = plaintextBytes[:]
        S = self.S
        i = self.i
        j = self.j
        for x in range(len(ciphertextBytes)):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % 256
            ciphertextBytes[x] ^= S[t]
        self.i = i
        self.j = j
        return ciphertextBytes

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)


from SocketIOTunnel.utils import logger
import hashlib

__all__ = ['ciphers']


class PyRC4Crypto(RC4):
    def __init__(self, cipher_name, key, iv, op):
        self.key = key
        self.iv = iv
        self._op = op
        self.cipher_name = cipher_name
        super(PyRC4Crypto, self).__init__(self.key)

    def update(self, data):
        if self._op:
            return self.encrypt(data)
        else:
            return self.encrypt(data)


class PyRC4MD5Crypto(PyRC4Crypto):
    def __init__(self, cipher_name, key, iv, op):
        md5 = hashlib.md5()
        md5.update(key)
        md5.update(iv)
        rc4_key = md5.digest()
        super(PyRC4MD5Crypto, self).__init__(cipher_name, rc4_key, iv, op)


ciphers = {
    'rc4': (16, 0, PyRC4Crypto),
    'rc4-md5': (16, 16, PyRC4MD5Crypto),
    'rc4-md5-6': (16, 6, PyRC4MD5Crypto),
}
