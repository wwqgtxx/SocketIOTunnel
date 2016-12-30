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
import socketio
import socket
from gevent import pywsgi
import traceback
import logging

sio = socketio.Server(async_mode="gevent")

logging.getLogger("socketio").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.ERROR)
logging.getLogger("geventwebsocket.handler").setLevel(logging.ERROR)

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

    def _read_socket_thread(self):
        try:
            while not self.disconnected:
                # logger.info("start _read_socket")
                data = self._read_socket()
                logger.debug("receive:%s" % data)
                data = self.data_parser.encode(data)
                # logger.info(data)
                sio.emit("data", data, namespace=self.namespace, room=self.room)
                # logger.info("finish to send to <%s,%s>" % (self.namespace, self.room))
        except ConnectionError:
            self.disconnect()
        except OSError:
            self.disconnect()

    def start(self):
        sio.start_background_task(self._read_socket_thread)

    def connect(self):
        self.socket.connect((self.upstream_ip, self.upstream_port))

    def message(self, data):
        data = self.data_parser.decode(data)
        logger.debug("send %s" % data)
        self._write_socket(data)
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


@sio.on('connect')
def connect(sid, environ):
    namespace = '/'
    room = sid
    logger.debug('connect %s' % sid)
    sis = SocketIOServer(globals()["upstream_ip"], globals()["upstream_port"], sid, namespace, room,
                         globals()["data_parser"])
    sis.connect()
    sis.start()
    connect_pool[sid] = sis


@sio.on('data')
def data(sid, data):
    sis = connect_pool[sid]
    # logger.info(data)
    sis.message(data)


@sio.on('disconnect')
def disconnect(sid):
    logger.debug('disconnect %s' % sid)
    sis = connect_pool[sid]
    sis.disconnect()
    try:
        connect_pool[sid] = None
        del sis
        del connect_pool[sid]
    except KeyError:
        logger.warning("can't delete {%s,%s}" % (sid, sis))


def main(ip="0.0.0.0", port=10010, upstream_ip="127.0.0.1", upstream_port=1080, password='password'):
    globals()["upstream_ip"] = upstream_ip
    globals()["upstream_port"] = upstream_port
    globals()["data_parser"] = DataParser(password)
    logger.info("start server on %s:%d" % (ip, port))
    try:
        from geventwebsocket.handler import WebSocketHandler
    except ImportError:
        WebSocketHandler = None
        logger.warning("can't import geventwebsocket.handler.WebSocketHandler!")
    pywsgi.WSGIServer((ip, port), app, handler_class=WebSocketHandler).serve_forever()


if __name__ == '__main__':
    main()
