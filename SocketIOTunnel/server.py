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

try:
    from .utils import logger, base64_encode, base64_decode
except SystemError:
    from utils import logger, base64_encode, base64_decode
import flask
import flask_socketio
import socket
import gevent
import logging

app = flask.Flask(__name__)
socketio = flask_socketio.SocketIO(app, async_mode="gevent")
logging.getLogger("socketio").setLevel(logging.WARNING)
logging.getLogger("engineio").setLevel(logging.WARNING)

connect_pool = dict()


class SocketIOServer(object):
    def __init__(self, server_ip, server_port, sid, namespace, room):
        self.server_ip = server_ip
        self.server_port = server_port
        self.namespace = namespace
        self.sid = sid
        self.room = room
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
                logger.info("receive:%s" % data)
                data = base64_encode(data)
                # logger.info(data)
                socketio.emit("data", data, namespace=self.namespace, room=self.room)
                # logger.info("finish to send to <%s,%s>" % (self.namespace, self.room))
        except ConnectionError:
            logger.info("disconnect")
        finally:
            self.disconnect()

    def start(self):
        socketio.start_background_task(self._read_socket_thread)

    def connect(self):
        self.socket.connect((self.server_ip, self.server_port))

    def message(self, data):
        data = base64_decode(data, bytes)
        logger.info("send %s" % data)
        self._write_socket(data)
        # logger.info("finish _write_socket")

    def disconnect(self):
        if not self.disconnected:
            logger.info("close socket")
            self.disconnected = True
            self.socket.close()
            socketio.server.disconnect(self.sid,
                                       namespace=self.namespace)


@app.route('/')
def index():
    return ""


@socketio.on('connect')
def connect():
    sid = flask.request.sid
    namespace = flask.request.namespace
    room = flask.request.sid
    logger.info('connect %s' % sid)
    sis = SocketIOServer(globals()["server_ip"], globals()["server_port"], sid, namespace, room)
    sis.connect()
    sis.start()
    connect_pool[sid] = sis


@socketio.on('data')
def data(data):
    sid = flask.request.sid
    sis = connect_pool[sid]
    # logger.info(data)
    sis.message(data)


@socketio.on('disconnect')
def disconnect():
    sid = flask.request.sid
    logger.info('disconnect %s' % sid)
    sis = connect_pool[sid]
    sis.disconnect()


def main(ip="0.0.0.0", port=10010, server_ip="127.0.0.1", server_port=1080):
    globals()["server_ip"] = server_ip
    globals()["server_port"] = server_port
    logger.info("start server on %s:%d" % (ip, port))
    socketio.run(app, host=ip, port=port, debug=False)


if __name__ == '__main__':
    main()
