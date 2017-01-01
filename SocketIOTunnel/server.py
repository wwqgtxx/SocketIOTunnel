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

from SocketIOTunnel.utils import logger
from SocketIOTunnel.dataparse import DataParser
from SocketIOTunnel.encrypt import method_supported
import socketio
import socket
from gevent import pywsgi
import traceback
import logging
from argparse import ArgumentParser

logging.getLogger("socketio").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.ERROR)
logging.getLogger("geventwebsocket.handler").setLevel(logging.ERROR)
sio = socketio.Server(async_mode="gevent")

connect_pool = dict()


class Middleware(socketio.Middleware):
    def __call__(self, environ, start_response):
        try:
            return super(Middleware, self).__call__(environ, start_response)
        except KeyError:
            return
        except:
            logger.exception("%s" % environ)
            start_response("503 Service Unavailable", [('Content-type', 'text/plain')])
            return [traceback.format_exc()]


app = Middleware(sio)


class SocketIOServer(object):
    def __init__(self, upstream_ip, upstream_port, sid, namespace, room, data_parser):
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port
        self.namespace = namespace
        self.sid = sid
        self.room = room
        self.data_parser = data_parser
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.disconnected = False

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

    def _read_socket_thread(self):
        try:
            while not self.disconnected:
                # logger.info("start _read_socket")
                data = self._read_socket()
                logger.debug("receive:%s" % data)
                self._send_data_to_client(data)
        except ConnectionError:
            self.disconnect()
        except OSError:
            self.disconnect()

    def _send_data_to_client(self, bytes_data, bytes_data_type=None):
        str_data = self.data_parser.encode(bytes_data, bytes_data_type)
        # logger.info(data)
        sio.emit("data", str_data, namespace=self.namespace, room=self.room)
        # logger.info("finish to send to <%s,%s>" % (self.namespace, self.room))

    def start(self):
        sio.start_background_task(self._read_socket_thread)

    def connect(self):
        self.socket.connect((self.upstream_ip, self.upstream_port))

    def message(self, data):
        bytes_data, data_type = self.data_parser.decode(data)
        if data_type == DataParser.DATA_TYPE["encrypt_handshake"]:
            logger.debug("reecive client encrypt_handshake")
            method = bytes_data.decode()
            if method_supported.get(str(method), None):
                self.data_parser.set_method(method)
                self._send_data_to_client(b"ok", DataParser.DATA_TYPE["encrypt_handshake"])
            else:
                self._send_data_to_client(b"no", DataParser.DATA_TYPE["encrypt_handshake"])
            return
        if bytes_data:
            logger.debug("send %s" % bytes_data)
            self._write_socket(bytes_data)
            # logger.info("finish _write_socket")

    def disconnect(self):
        if not self.disconnected:
            logger.debug("close socket %s" % self.socket)
            self.disconnected = True
            try:
                self.socket.close()
            except:
                logger.warning("error close socket", exc_info=True)
            try:
                sio.disconnect(self.sid, namespace=self.namespace)
            except:
                logger.warning("error close socketio", exc_info=True)

    def __del__(self):
        self.disconnect()


@sio.on('connect')
def connect(sid, environ):
    namespace = '/'
    room = sid
    logger.debug('connect %s' % sid)
    sis = SocketIOServer(globals()["upstream_ip"], globals()["upstream_port"], sid, namespace, room,
                         DataParser(globals()["password"]))
    sis.connect()
    sis.start()
    connect_pool[sid] = sis


@sio.on('data')
def data(sid, data):
    sis = connect_pool.get(sid, None)
    if sis and not sis.disconnected:
        # logger.info(data)
        sis.message(data)
    else:
        connect_pool[sid] = None
        del connect_pool[sid]
        sio.disconnect(sid=sid)


@sio.on('disconnect')
def disconnect(sid):
    logger.debug('disconnect %s' % sid)
    sis = connect_pool[sid]
    sis.disconnect()
    try:
        connect_pool[sid] = None
        del connect_pool[sid]
    except KeyError:
        logger.warning("can't delete {%s,%s}" % (sid, sis))


def main(ip="0.0.0.0", port=10010, upstream_ip="127.0.0.1", upstream_port=1080, password='password'):
    parser = ArgumentParser(description="SocketIOTunnel Server")
    parser.add_argument('--ip', type=str, default=ip,
                        help="set listening ip")
    parser.add_argument('--port', type=int, default=port,
                        help="set listening port")
    parser.add_argument('--upstream_ip', type=str, default=upstream_ip,
                        help="set upstream ip")
    parser.add_argument('--upstream_port', type=int, default=upstream_port,
                        help="set upstream port")
    parser.add_argument('--password', type=str, default=password,
                        help="the password used to connect")

    args = parser.parse_args()
    globals()["upstream_ip"] = args.upstream_ip
    globals()["upstream_port"] = args.upstream_port
    globals()["password"] = args.password
    logger.info("start server on %s:%d" % (args.ip, args.port))
    try:
        from geventwebsocket.handler import WebSocketHandler
    except ImportError:
        WebSocketHandler = None
        logger.warning("can't import geventwebsocket.handler.WebSocketHandler!")
    pywsgi.WSGIServer((args.ip, args.port), app, handler_class=WebSocketHandler).serve_forever()


if __name__ == '__main__':
    main()
