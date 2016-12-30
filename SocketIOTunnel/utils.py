#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future import standard_library

standard_library.install_aliases()
from builtins import *

import sys
import os
import threading
import subprocess
import multiprocessing
import time
import base64

import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s{%(name)s}%(filename)s[line:%(lineno)d]<%(funcName)s> pid:%(process)d %(threadName)s %(levelname)s : %(message)s',
                    datefmt='%H:%M:%S', stream=sys.stdout)

logger = logging.getLogger("SocketIOTunnel")

try:
    import PyCRC.CRC16
    import PyCRC.CRC32
    import PyCRC.CRC16DNP
    import PyCRC.CRC16Kermit
    import PyCRC.CRC16SICK
    import PyCRC.CRCCCITT

    crc16 = PyCRC.CRC16.CRC16().calculate
    crc32 = PyCRC.CRC32.CRC32().calculate
    crc16dnp = PyCRC.CRC16DNP.CRC16DNP().calculate
    crc16kermit = PyCRC.CRC16Kermit.CRC16Kermit().calculate
    crc16sick = PyCRC.CRC16SICK.CRC16SICK().calculate
    crccitt = PyCRC.CRCCCITT.CRCCCITT().calculate
except ImportError:
    crc16 = None
    crc32 = None
    crc16dnp = None
    crc16kermit = None
    crc16sick = None
    crccitt = None


def base64_encode(input_data, return_type=str, encoding="utf-8"):
    is_string = isinstance(input_data, str)
    is_bytes = isinstance(input_data, bytes)
    if not is_string and not is_bytes:
        raise Exception("Please provide a string or a byte sequence ")
    if is_bytes:
        bytes_string = input_data
    else:
        bytes_string = input_data.encode(encoding=encoding)
    result = base64.b64encode(bytes_string)
    if return_type is str:
        return result.decode()
    else:
        return result


def base64_decode(input_data, return_type=str, encoding="utf-8"):
    is_string = isinstance(input_data, str)
    is_bytes = isinstance(input_data, bytes)
    if not is_string and not is_bytes:
        raise Exception("Please provide a string or a byte sequence ")
    if is_bytes:
        bytes_string = input_data
    else:
        bytes_string = input_data.encode(encoding=encoding)
    result = base64.b64decode(bytes_string)
    if return_type is str:
        return result.decode()
    else:
        return result


MAIN_PATH = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "./__init__.py"))


def get_real_path(abstract_path):
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(MAIN_PATH)), abstract_path))


try:
    import configparser

    CONFIG = configparser.ConfigParser()
    CONFIG.read(get_real_path('config.ini'))
except ImportError:
    CONFIG = None


def get_config(key):
    return CONFIG[key]


def run_process(args, need_wait=True, before_wait=None, ignore_error=True, *k, **kk):
    logger.info("launch {%s}" % (" ".join(args)))
    try:
        p = subprocess.Popen(args=args, *k, **kk)
        if before_wait:
            before_wait()
        if need_wait:
            p.wait()
        return p
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except Exception as e:
        if not ignore_error:
            raise e
        else:
            logger.debug(e)


def run_python_process(target, args=(), kwargs=None, need_join=True, before_join=None, join_timeout=None,
                       auto_restart=True, retry_time=3):
    process = multiprocessing.Process(target=target, args=args, kwargs=kwargs)
    process.start()
    if before_join:
        before_join()
    if auto_restart:
        daemon_thread = join_and_auto_restart_process(process, retry_time, need_join, join_timeout)
        daemon_thread.start()
        if need_join:
            daemon_thread.join(join_timeout)
        return daemon_thread
    else:
        if need_join:
            process.join(join_timeout)
        return process


def join_and_auto_restart_process(process, retry_time=3, need_join=True, join_timeout=None):
    def daemon_thread_runner():
        failed_time = 0
        _process = process
        while True:
            logger.info("join " + str(process))
            process.join()
            logger.info(str(process) + "was exited")
            if process.exitcode == 100:
                raise KeyboardInterrupt
            failed_time += 1
            if retry_time and failed_time > retry_time:
                break
            time.sleep(1)
            _process = multiprocessing.Process(target=_process._target, args=_process._args, kwargs=_process._kwargs)
            logger.info("start " + str(process))
            process.start()

    daemon_thread = threading.Thread(target=daemon_thread_runner)
    daemon_thread.start()
    if need_join:
        daemon_thread.join(timeout=join_timeout)
    return daemon_thread


def join_threads_or_process(threads_or_process):
    for i in threads_or_process:
        i.join()


def create_file(filename):
    if not os.path.exists(filename):
        logger.info("create %s" % filename)
        os.mknod(filename)
