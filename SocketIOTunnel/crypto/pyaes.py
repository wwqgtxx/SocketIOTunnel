#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>

from __future__ import absolute_import, division, print_function, \
    with_statement
from SocketIOTunnel.utils import logger
import pyaes

__all__ = ['ciphers']


class PyAESCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
        self.key = key
        self.iv = iv
        self._op = op
        self.cipher_name = cipher_name
        self.segment_size = 0
        if "cfb" in self.cipher_name:
            if self.cipher_name.endswith("cfb8"):
                self.segment_size = 8
            elif self.cipher_name.endswith("cfb1"):
                self.segment_size = 0
            else:
                self.segment_size = 128
            self.aes = pyaes.AESModeOfOperationCFB(self.key, iv=self.iv, segment_size=self.segment_size)
        elif "cbc" in self.cipher_name:
            self.aes = pyaes.AESModeOfOperationCBC(self.key, iv=self.iv)
            self.segment_size = 16
        elif "ofb" in self.cipher_name:
            self.aes = pyaes.AESModeOfOperationOFB(self.key, iv=self.iv)
        elif "ctr" in self.cipher_name:
            self.aes = pyaes.AESModeOfOperationCTR(self.key)

    def update(self, data):
        if self._op:
            if self.segment_size:
                result = b''
                encrypter = pyaes.Encrypter(self.aes)
                result += encrypter.feed(data)
                result += encrypter.feed()
                return result
            else:
                return self.aes.encrypt(data)
        else:
            if self.segment_size:
                result = b''
                decrypter = pyaes.Decrypter(self.aes)
                result += decrypter.feed(data)
                result += decrypter.feed()
                return result
            else:
                return self.aes.decrypt(data)


ciphers = {
    'aes-128-ofb': (16, 16, PyAESCrypto),
    'aes-192-ofb': (24, 16, PyAESCrypto),
    'aes-256-ofb': (32, 16, PyAESCrypto),
    # 'aes-128-cbc': (16, 16, PyAESCrypto),
    # 'aes-192-cbc': (24, 16, PyAESCrypto),
    # 'aes-256-cbc': (32, 16, PyAESCrypto),
    # 'aes-128-cfb': (16, 16, PyAESCrypto),
    # 'aes-192-cfb': (24, 16, PyAESCrypto),
    # 'aes-256-cfb': (32, 16, PyAESCrypto),
    # 'aes-128-ctr': (16, 16, PyAESCrypto),
    # 'aes-192-ctr': (24, 16, PyAESCrypto),
    # 'aes-256-ctr': (32, 16, PyAESCrypto),
    # 'aes-128-cfb8': (16, 16, PyAESCrypto),
    # 'aes-192-cfb8': (24, 16, PyAESCrypto),
    # 'aes-256-cfb8': (32, 16, PyAESCrypto),
    # 'aes-128-cfb1': (16, 16, PyAESCrypto),
    # 'aes-192-cfb1': (24, 16, PyAESCrypto),
    # 'aes-256-cfb1': (32, 16, PyAESCrypto),
}
