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
from SocketIOTunnel.socketIO_client import SocketIO, LoggingNamespace
from SocketIOTunnel.encrypt import method_supported, BASE_ENCRYPT_METHOD
from SocketIOTunnel.utils import logger
from SocketIOTunnel.dataparse import DataParser
import logging
from argparse import ArgumentParser

logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("socketIO-client").setLevel(logging.ERROR)

try:
    from ssl import SSLError
except ImportError:
    class SSLError(Exception):
        pass

import websocket

websocket.SSLError = SSLError


class SocketIOClient(object):
    def __init__(self, socket, address, server_ip, server_port, password, method):
        self.socket = socket
        self.address = address
        self.server_ip = server_ip
        self.server_port = server_port
        self.password = password
        self.method = method
        self.data_parser = DataParser(password, globals()["server_support_method"])
        self.socketIO = None
        self.disconnected = False

    def _on_connect(self):
        pass

    def _on_disconnect(self):
        if not self.disconnected:
            logger.debug("disconnect <%s>" % self.socket)
            self.disconnected = True
            self.socket.close()

    def _on_reconnect(self):
        pass

    def _on_data(self, data):
        bytes_data, data_type = self.data_parser.decode(data)
        if data_type == DataParser.DATA_TYPE["encrypt_handshake"]:
            self._set_method(bytes_data.decode())
        if bytes_data:
            logger.debug("receive:%s" % bytes_data)
            try:
                self._write_socket(bytes_data)
            except OSError:
                self.disconnect()
            except:
                logger.warning("error write socket", exc_info=True)
                self.disconnect()

    def connect(self):
        self.socketIO = SocketIO(self.server_ip, self.server_port, LoggingNamespace)
        self.socketIO.on('connect', self._on_connect)
        self.socketIO.on('disconnect', self._on_disconnect)
        self.socketIO.on('reconnect', self._on_reconnect)
        self.socketIO.on('data', self._on_data)
        logger.debug("transport selected: %s" % self.socketIO.transport_name)

    def disconnect(self):
        if not self.disconnected:
            logger.debug("disconnect <%s>" % self.socket)
            self.disconnected = True
            try:
                self.socket.close()
            except:
                logger.warning("error close socket", exc_info=True)
            self.socketIO.disconnect()

    def _read_socket(self, buffer_size=1024, need_decode=False, encoding="utf-8", errors="ignore"):
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
            try:
                self.socketIO.wait()
            except IndexError:
                logger.warning("IndexError", exc_info=True)

    def _set_method(self, data):
        if data == "ok":
            self.data_parser.set_method(self.method)
            globals()["server_support_method"] = self.method
            logger.info("get server support your method ,set encrypt method to %s" % self.method)
        else:
            logger.warning("server not support your method %s ,force set %s" % (self.method, BASE_ENCRYPT_METHOD))
            self.data_parser.set_method(BASE_ENCRYPT_METHOD)
            self.method = BASE_ENCRYPT_METHOD
            globals()["method"] = BASE_ENCRYPT_METHOD
            globals()["server_support_method"] = BASE_ENCRYPT_METHOD

    def _send_data_to_server(self, bytes_data, bytes_data_type=None):
        if self.socketIO.transport_name != 'websocket':
            return_data = self.data_parser.encode(bytes_data, bytes_data_type, return_type=str)
        else:
            return_data = self.data_parser.encode(bytes_data, bytes_data_type)
        if not return_data:
            return
        if isinstance(return_data, bytes):
            return_data = bytearray(return_data)
        self.socketIO.emit("data", return_data)

    def start(self):
        if not globals()["server_support_method"] and self.method != BASE_ENCRYPT_METHOD:
            logger.info("first use %s and send a encrypt_handshake a server" % (BASE_ENCRYPT_METHOD))
            self._send_data_to_server(self.method.encode(), DataParser.DATA_TYPE["encrypt_handshake"])
        gevent.spawn(self._wait_message_thread)
        try:
            while not self.disconnected:
                data = self._read_socket()
                logger.debug("send %s" % data)
                self._send_data_to_server(data)
        except OSError:
            self.disconnect()


def socket_handle(socket, address):
    logger.debug("new client<%s> connect" % str(address))
    sic = SocketIOClient(socket, address, globals()["server_ip"], globals()["server_port"], globals()["password"],
                         globals()["method"])
    try:
        sic.connect()
        sic.start()
    except ConnectionError:
        logger.debug("client<%s> disconnect" % str(address))
    finally:
        sic.disconnect()


def main(ip="0.0.0.0", port=10011, server_ip="127.0.0.1", server_port=10010, password='password',
         method='chacha20'):
    parser = ArgumentParser(description="SocketIOTunnel Client")
    parser.add_argument('--ip', type=str, default=ip,
                        help="set listening ip")
    parser.add_argument('--port', type=int, default=port,
                        help="set listening port")
    parser.add_argument('--server_ip', type=str, default=server_ip,
                        help="set server ip")
    parser.add_argument('--server_port', type=int, default=server_port,
                        help="set server port")
    parser.add_argument('--password', type=str, default=password,
                        help="the password used to connect")
    parser.add_argument('--method', type=str, default=method,
                        help="the encrypt method used to connect")

    args = parser.parse_args()
    globals()["server_ip"] = args.server_ip
    globals()["server_port"] = args.server_port
    globals()["password"] = args.password
    if method_supported.get(args.method, None):
        globals()["method"] = args.method
    else:
        logger.warning("client not support your method %s ,force set to %s" % (args.method, BASE_ENCRYPT_METHOD))
        globals()["method"] = BASE_ENCRYPT_METHOD
    globals()["server_support_method"] = None
    logger.info("start client on %s:%d" % (args.ip, args.port))
    server = StreamServer((args.ip, args.port), socket_handle)
    server.init_socket()
    server.serve_forever()


if __name__ == '__main__':
    main()
