#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import imp
import pwd
import sys

from flask import Flask, request, jsonify, make_response
from pdb import set_trace as breakpoint
from pprint import pformat

from utils.fmt import *
from lea import app

STATUS_CODES = {
    400: 'bad request',
    401: 'unauthorized',
    402: 'payment required',
    403: 'forbidden',
    404: 'not found',
    405: 'method not allowed',
    406: 'not acceptable',
    407: 'proxy authentication required',
    408: 'request timed-out',
    409: 'conflict',
    410: 'gone',
    411: 'length required',
    412: 'precondition failed',
    413: 'payload too large',
    414: 'uri too long',
    415: 'unsupported media type',
    416: 'range not satisfiable',
    417: 'expectation failed',
    418: 'im a teapot',
    421: 'misdirected request',
    422: 'unprocessable entity',
    423: 'locked',
    424: 'failed dependency',
    426: 'upgrade required',
    428: 'precondition required',
    429: 'too many requires',
    431: 'request header fields too large',
    451: 'unavailable for legal reasons',

    500: 'internal server error',
    501: 'not implemented',
    502: 'bad gateway',
    503: 'service unavailable',
    504: 'gateway timed out',
    505: 'http version not supported',
    506: 'variant also negotiates',
    507: 'insufficient storage',
    508: 'loop detected',
    510: 'not extended',
    511: 'network authentication required',
}

LOGGING_LEVELS = {
    0: 'NOTSET',
    10: 'DEBUG',
    20: 'INFO',
    30: 'WARN',
    40: 'ERROR',
    50: 'FATAL',
}

class EmptyJsonError(AutocertError):
    def __init__(self, json):
        message = fmt('empty json error ={0}', json)
        super(EmptyJsonError, self).__init__(message)

@app.before_first_request
def initialize():
    from logging import getLogger
    from logging.config import dictConfig
    from config import CFG
    if sys.argv[0] != 'venv/bin/pytest':
        dictConfig(CFG.logging)     #3
        LEVEL = LOGGING_LEVELS[getLogger('api').getEffectiveLevel()]
        PID = os.getpid()
        PPID = os.getppid()
        USER = pwd.getpwuid(os.getuid())[0]
        pfmt('starting lea api with log level={LEVEL}, pid={PID}, ppid={PPID} by user={USER}')

def log_request(user, hostname, ip, method, path, json):
    app.logger.info(fmt('{user}@{hostname} from {ip} ran {method} {path} with json=\n"{json}"'))

@app.route('/lea/version', methods=['GET'])
def version():
    args = request.json
    args = args if args else {}
    cfg = args.get('cfg', None)
    log_request(
        args.get('user', 'unknown'),
        args.get('hostname', 'unknown'),
        request.remote_addr,
        request.method,
        request.path,
        args)
    from utils.version import version
    return jsonify(dict(version=version))

@app.route('/lea/config', methods=['GET'])
def config():
    args = request.json
    args = args if args else {}
    cfg = args.get('cfg', None)
    log_request(
        args.get('user', 'unknown'),
        args.get('hostname', 'unknown'),
        request.remote_addr,
        request.method,
        request.path,
        args)
    from config import _load_config
    cfg = _load_config(fixup=False)
    return jsonify({'config': cfg})

@app.route('/lea', methods=['GET', 'PUT', 'POST', 'DELETE'])
def route():
    args = request.json
    args = args if args else {}
    cfg = args.get('cfg', None)
    log_request(
        args.get('user', 'unknown'),
        args.get('hostname', 'unknown'),
        request.remote_addr,
        request.method,
        request.path,
        args)
    try:
        endpoint = create_endpoint(request.method, cfg, args)
        json, status = endpoint.execute()
    except Exception as ex:
        status = 500
        json = dict(errors={ex.__class__.__name__: sys.exc_info()[0]})
    if not json:
        raise EmptyJsonError(json)
    return make_response(jsonify(json), status)

@app.errorhandler(Exception)
def unhandled_exception(ex):
    app.logger.error('unhandled exception', exc_info=True)

if __name__ == '__main__':
    app.run()
