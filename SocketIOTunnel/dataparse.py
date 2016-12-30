#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future import standard_library

standard_library.install_aliases()
from builtins import *

from SocketIOTunnel.utils import logger, base64_encode, base64_decode, crc32
from SocketIOTunnel.encrypt import encrypt_all, method_to_id, id_to_method


class Encryptor(object):
    def __init__(self, password='password', method='chacha20'):
        self.password = password
        self.method = method

    def encrypt(self, bytes_data):
        plain = bytes_data
        cipher = encrypt_all(self.password, self.method, 1, plain)
        data = b'%02x%s' % (method_to_id[self.method], cipher)
        return data

    def decrypt(self, bytes_data):
        method = id_to_method[int(bytes_data[:2], 16)]
        cipher = bytes_data[2:]
        plain = encrypt_all(self.password, method, 0, cipher)
        return plain


class DataParser(object):
    def __init__(self, encryptor=Encryptor()):
        self.encryptor = encryptor

    def encode(self, bytes_data):
        if bytes_data:
            try:
                if self.encryptor:
                    data = self.encryptor.encrypt(bytes_data)
                    # logger.info(data)
                else:
                    data = bytes_data
                base64_data = base64_encode(data, return_type=str)
                raw_crc = crc32(bytes_data)
                crc = crc32(base64_data)
                str_data = "%08x%08x%s" % (crc, raw_crc, base64_data)
                return str_data
            except:
                logger.exception("encode error!")
        return ''

    def decode(self, str_data):
        if str_data:
            try:
                crc = int(str_data[:8], 16)
                raw_crc = int(str_data[8:16], 16)
                base64_data = str_data[16:]
                data_crc = crc32(base64_data)
                if crc and crc != data_crc:
                    logger.warning("crc error!,<%08x>!=<%08x>" % (crc, data_crc))
                bytes_data = base64_decode(base64_data, return_type=bytes)
                if self.encryptor:
                    data = self.encryptor.decrypt(bytes_data)
                    # logger.info(data)
                    if isinstance(data, str):
                        bytes_data = data.encode(encoding="utf-8", errors="ignore")
                    else:
                        bytes_data = data
                raw_data_crc = crc32(bytes_data)
                if raw_crc and raw_crc != raw_data_crc:
                    logger.warning("crc error!,<%08x>!=<%08x>" % (raw_crc, raw_data_crc))
                return bytes_data
            except:
                logger.exception("decode error!")
        return b''
