#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future import standard_library

standard_library.install_aliases()
from builtins import *

from SocketIOTunnel.utils import logger, base64_encode, base64_decode, base85_encode, base85_decode, crc32
from SocketIOTunnel.encrypt import encrypt_all, method_to_id, id_to_method, method_supported, BASE_ENCRYPT_METHOD
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
            method = BASE_ENCRYPT_METHOD
        else:
            method = self.method
        plain = bytes_data
        try:
            cipher = encrypt_all(self.password, method, 1, plain)
        except AssertionError:
            raise UnsupportEncryptMethod(self.method)
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
        if not self.method and method != BASE_ENCRYPT_METHOD:
            self.method = method
            # logger.info("auto set encrypt method: %s" % method)
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
    DATA_TYPE = {
        "raw_data": 0,
        "encrypt_data": 1,
        "encrypt_handshake": 2,
    }

    def __init__(self, password, method=None, encode_return_type=bytes):
        self.password = password
        self.method = method
        self.encryptor = Encryptor(password, method)
        self.compresstor = Compresstor()
        self.encoder = Encoder()
        self.encode_return_type = encode_return_type

    def set_method(self, method):
        # logger.info("set encrypt method: %s" % method)
        self.method = method
        self.encryptor = Encryptor(self.password, method)

    def encode(self, bytes_data, bytes_data_type=None, return_type=None):
        if not return_type:
            return_type = self.encode_return_type
        if bytes_data:
            try:
                if self.encryptor and bytes_data_type != DataParser.DATA_TYPE["raw_data"]:
                    data_type = DataParser.DATA_TYPE["encrypt_data"]
                    data = self.encryptor.encrypt(bytes_data)
                    # logger.info(data)
                else:
                    data_type = DataParser.DATA_TYPE["raw_data"]
                    data = bytes_data
                if bytes_data_type:
                    data_type = bytes_data_type
                raw_crc = crc32(bytes_data)
                head = struct.pack(">IB", raw_crc, data_type)
                data = head + data
                data = self.compresstor.compress(data)
                if return_type == str:
                    data = self.encoder.encode(data, return_type=str)
                    crc = crc32(data)
                    str_data = "%08x%s" % (crc, data)
                    return str_data
                else:
                    crc = crc32(data)
                    output_bytes_data = struct.pack(">I", crc)
                    output_bytes_data += data
                    return output_bytes_data
            except UnsupportEncryptMethod:
                logger.warning(
                    "client not support your method %s ,force set to %s" % (self.method, BASE_ENCRYPT_METHOD))
                self.set_method(BASE_ENCRYPT_METHOD)
                return self.encode(bytes_data)
            except:
                logger.exception("encode error!")
        if return_type == bytes:
            return b''
        else:
            return ''

    def decode(self, input_data):
        if input_data:
            try:
                # length0 = len(input_data)
                if isinstance(input_data, bytearray):
                    input_data = bytes(input_data)
                if isinstance(input_data, bytes):
                    crc = struct.unpack(">I", input_data[:4])[0]
                    data = input_data[4:]
                else:
                    crc = int(input_data[:8], 16)
                    data = input_data[8:]
                data_crc = crc32(data)
                if crc and crc != data_crc:
                    raise CRCError("crc error!,<%08x>!=<%08x>" % (crc, data_crc))
                if isinstance(input_data, str):
                    bytes_data = self.encoder.decode(data, return_type=bytes)
                else:
                    bytes_data = data
                bytes_data = self.compresstor.decompress(bytes_data)
                raw_crc, data_type = struct.unpack(">IB", bytes_data[:5])
                bytes_data = bytes_data[5:]
                if data_type == DataParser.DATA_TYPE["encrypt_handshake"]:
                    if isinstance(input_data, str):
                        self.encode_return_type = str
                if not data_type == DataParser.DATA_TYPE["raw_data"]:
                    data = self.encryptor.decrypt(bytes_data)
                    # logger.info(data)
                    if isinstance(data, str):
                        bytes_data = data.encode(encoding="utf-8", errors="ignore")
                    else:
                        bytes_data = data
                raw_data_crc = crc32(bytes_data)
                if raw_crc and raw_crc != raw_data_crc:
                    raise CRCError("crc error!,<%08x>!=<%08x>,raw data is:%s" % (raw_crc, raw_data_crc, bytes_data))
                # length1 = len(bytes_data)
                # logger.info("%.02f%%" % (length0 / length1 * 100))
                return bytes_data, data_type
            # except DataParseError as e:
            #     raise e
            except:
                logger.exception("decode error!")
        return b'', DataParser.DATA_TYPE["raw_data"]
