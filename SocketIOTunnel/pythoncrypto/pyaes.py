#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>

from __future__ import absolute_import, division, print_function, \
    with_statement
from SocketIOTunnel.utils import logger
import pyaes

__all__ = ['ciphers']


def pad_pkcs5(data):
    return pad_pkcs7(data, 8)


def unpad_pkcs5(data):
    return unpad_pkcs7(data)


def pad_pkcs7(data, block_size):
    padding = block_size - (len(data) % block_size)
    pattern = chr(padding).encode()
    return data + pattern * padding


def unpad_pkcs7(data):
    pattern = data[-1:]
    length = ord(pattern.decode())
    padding = pattern * length
    pattern_pos = len(data) - length
    logger.info(data[pattern_pos:])
    if data[pattern_pos:] == padding:
        return data[0: pattern_pos]
    return data


class PyAESCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
        self.key = key
        self.iv = iv
        self._op = op
        self.cipher_name = cipher_name
        self.segment_size = 0
        self.pad_mode = "pkcs7"
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
                if self.pad_mode == "pkcs7":
                    data = pad_pkcs7(data, self.segment_size)
                    for i in range(0, len(data), self.segment_size):
                        result += self.aes.encrypt(data[i:i + self.segment_size])
                else:
                    encrypter = pyaes.Encrypter(self.aes)
                    result += encrypter.feed(data)
                    result += encrypter.feed()
                return result
            else:
                return self.aes.encrypt(data)
        else:
            if self.segment_size:
                result = b''
                if self.pad_mode == "pkcs7":
                    result += self.aes.decrypt(data)
                    result = unpad_pkcs7(result)
                else:
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
