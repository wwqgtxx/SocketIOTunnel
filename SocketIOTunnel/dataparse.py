#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future import standard_library

standard_library.install_aliases()
from builtins import *

from SocketIOTunnel.utils import logger, base64_encode, base64_decode, base85_encode, base85_decode, crc32
from SocketIOTunnel.encrypt import encrypt_all, method_to_id, id_to_method, method_supported
import lz4
import struct


class DataParseError(RuntimeError):
    pass


class UnsupportEncryptMethod(DataParseError):
    pass


class CRCError(DataParseError):
    pass


class Encryptor(object):
    def __init__(self, password, method=None):
        if isinstance(password, str):
            password = password.encode()
        self.password = password
        self.method = method

    def encrypt(self, bytes_data):
        if not self.method:
            method = 'aes-256-ofb'
        else:
            method = self.method
        plain = bytes_data
        cipher = encrypt_all(self.password, method, 1, plain)
        data = struct.pack("!B", method_to_id[method])  # byte format requires 0 <= number <= 255
        data += cipher
        return data

    def decrypt(self, bytes_data):
        try:
            method = id_to_method[struct.unpack("!B", bytes_data[:1])[0]]
        except:
            raise UnsupportEncryptMethod()
        if not method_supported.get(method, None):
            raise UnsupportEncryptMethod(method)
        if not self.method:
            self.method = method
            logger.info("auto set encrypt method: %s" % method)
        cipher = bytes_data[1:]
        plain = encrypt_all(self.password, method, 0, cipher)
        return plain


class Compresstor(object):
    def __init__(self, method="lz4"):
        self.method = method

    def compress(self, bytes_data):
        if self.method == "lz4":
            data = lz4.dumps(bytes_data)
        else:
            data = bytes_data
        return data

    def decompress(self, bytes_data):
        if self.method == "lz4":
            data = lz4.loads(bytes_data)
        else:
            data = bytes_data
        return data


class Encoder(object):
    def __init__(self, method="base85"):
        self.method = method

    def encode(self, input_data, return_type=str, encoding="utf-8"):
        if self.method == "base64":
            return base64_encode(input_data, return_type, encoding)
        else:
            return base85_encode(input_data, return_type, encoding)

    def decode(self, input_data, return_type=bytes, encoding="utf-8"):
        if self.method == "base64":
            return base64_decode(input_data, return_type, encoding)
        else:
            return base85_decode(input_data, return_type, encoding)


class DataParser(object):
    def __init__(self, password, method=None):
        logger.info("use encrypt method: %s" % method)
        self.encryptor = Encryptor(password, method)
        self.compresstor = Compresstor()
        self.encoder = Encoder()

    def encode(self, bytes_data):
        if bytes_data:
            try:
                if self.encryptor:
                    is_encrypt = 1
                    data = self.encryptor.encrypt(bytes_data)
                    # logger.info(data)
                else:
                    is_encrypt = 0
                    data = bytes_data
                raw_crc = crc32(bytes_data)
                head = struct.pack(">IB", raw_crc, is_encrypt)
                data = head + data
                data = self.compresstor.compress(data)
                encode_data = self.encoder.encode(data, return_type=str)
                crc = crc32(encode_data)
                str_data = "%08x%s" % (crc, encode_data)
                return str_data
            except:
                logger.exception("encode error!")
        return ''

    def decode(self, str_data):
        if str_data:
            try:
                # length0 = len(str_data)
                crc = int(str_data[:8], 16)
                encode_data = str_data[8:]
                data_crc = crc32(encode_data)
                if crc and crc != data_crc:
                    raise CRCError("crc error!,<%08x>!=<%08x>" % (crc, data_crc))
                bytes_data = self.encoder.decode(encode_data, return_type=bytes)
                bytes_data = self.compresstor.decompress(bytes_data)
                raw_crc, is_encrypt = struct.unpack(">IB", bytes_data[:5])
                bytes_data = bytes_data[5:]
                if is_encrypt:
                    data = self.encryptor.decrypt(bytes_data)
                    # logger.info(data)
                    if isinstance(data, str):
                        bytes_data = data.encode(encoding="utf-8", errors="ignore")
                    else:
                        bytes_data = data
                raw_data_crc = crc32(bytes_data)
                if raw_crc and raw_crc != raw_data_crc:
                    raise CRCError("crc error!,<%08x>!=<%08x>" % (raw_crc, raw_data_crc))
                # length1 = len(bytes_data)
                # logger.info("%.02f%%" % (length0 / length1 * 100))
                return bytes_data
            except DataParseError as e:
                raise e
            except:
                logger.exception("decode error!")
        return b''
