#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from gevent import monkey

monkey.patch_all()
from future import standard_library

standard_library.install_aliases()
from builtins import *
import gevent
from gevent.server import StreamServer
from socketIO_client import SocketIO, LoggingNamespace

try:
    from .utils import logger, base64_encode, base64_decode
except SystemError:
    from utils import logger, base64_encode, base64_decode
import logging

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("socketIO-client").setLevel(logging.WARNING)


class SocketIOClient(object):
    def __init__(self, socket, address, server_ip, server_port):
        self.socket = socket
        self.address = address
        self.server_ip = server_ip
        self.server_port = server_port
        self.socketIO = None
        self.disconnected = False

    def _on_connect(self):
        pass

    def _on_disconnect(self):
        if not self.disconnected:
            logger.info("disconnect")
            self.disconnected = True
            self.socket.close()

    def _on_reconnect(self):
        pass

    def _on_data(self, data):
        data = base64_decode(data, return_type=bytes)
        logger.info("receive:%s" % data)
        try:
            self._write_socket(data)
        except ConnectionAbortedError:
            self.disconnect()

    def connect(self):
        self.socketIO = SocketIO(self.server_ip, self.server_port, LoggingNamespace)
        self.socketIO.on('connect', self._on_connect)
        self.socketIO.on('disconnect', self._on_disconnect)
        self.socketIO.on('reconnect', self._on_reconnect)
        self.socketIO.on('data', self._on_data)

    def disconnect(self):
        if not self.disconnected:
            logger.info("disconnect")
            self.disconnected = True
            self.socket.close()
            self.socketIO.disconnect()

    def _read_socket(self, buffer_size=4096, need_decode=False, encoding="utf-8", errors="ignore"):
        data = self.socket.recv(buffer_size)
        if not data:
            raise ConnectionError()
        if need_decode:
            return data.decode(encoding=encoding, errors=errors)
        else:
            return data

    def _write_socket(self, data, need_encode=False, encoding="utf-8", errors="ignore"):
        if need_encode:
            data = data.encode(encoding=encoding, errors=errors)
        return self.socket.send(data)

    def _wait_message_thread(self):
        while not self.disconnected:
            self.socketIO.wait()

    def start(self):
        gevent.spawn(self._wait_message_thread)
        while not self.disconnected:
            data = self._read_socket()
            logger.info("send %s" % data)
            data = base64_encode(data)
            self.socketIO.emit("data", data)


def socket_handle(socket, address):
    logger.info("new client<%s> connect" % str(address))
    sic = SocketIOClient(socket, address, globals()["server_ip"], globals()["server_port"])
    try:
        sic.connect()
        sic.start()
    except ConnectionError:
        logger.info("client<%s> disconnect" % str(address))
    finally:
        sic.disconnect()


def main(ip="0.0.0.0", port=10011, server_ip="127.0.0.1", server_port=10010):
    globals()["server_ip"] = server_ip
    globals()["server_port"] = server_port
    logger.info("start client on %s:%d" % (ip, port))
    server = StreamServer((ip, port), socket_handle)
    server.init_socket()
    server.serve_forever()


if __name__ == '__main__':
    main()
