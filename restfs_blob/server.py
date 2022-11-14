#!/usr/bin/env python3

'''Blob server for RestFS'''

import sys
import shutil
import logging
import os.path
import argparse
import tempfile

from flask import Flask, make_response, request, send_from_directory

from restfs_client import get_AuthService
from restfs_common.errors import Unauthorized, ObjectNotFound, ObjectAlreadyExists,\
    AlreadyDoneError
from restfs_common.constants import HTTPS_DEBUG_MODE, ADMIN, ADMIN_TOKEN, USER_TOKEN,\
    DEFAULT_BLOB_SERVICE_PORT

from restfs_blob.service import BlobDB


def routeApp(app, BLOB, AUTH): # pylint: disable=too-many-statements
    '''Enruta la API REST a la webapp'''

    def _get_effective_user_(req):
        '''Get the user which send the request'''
        try:
            user = AUTH.user_of_token(req.headers.get(USER_TOKEN, None))
            return user
        except Unauthorized:
            if AUTH.is_admin(req.headers.get(ADMIN_TOKEN, None)):
                return ADMIN
        return None

    @app.route('/v1/blob/<blob_id>', methods=['GET'])
    def get_blob(blob_id):
        '''Descargar un blob'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if not BLOB.blob_exists(blob_id):
            return make_response('Blob not exists', 404)

        return send_from_directory(
            os.path.dirname(BLOB.blob_local_filename(blob_id)),
            os.path.basename(BLOB.blob_local_filename(blob_id)),
            as_attachment=True
        )

    @app.route('/v1/blob/<blob_id>', methods=['PUT'])
    def new_blob(blob_id):
        '''Crea un nuevo blob'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        try:
            BLOB.new_blob(blob_id, request.files[blob_id], user)
        except ObjectAlreadyExists:
            return make_response('Forbidden', 409)
        return make_response('Created', 201)

    @app.route('/v1/blob/<blob_id>', methods=['POST'])
    def update_blob(blob_id):
        '''Actualiza un blob'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        try:
            BLOB.update_blob(blob_id, request.files[blob_id], user)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        return make_response('', 204)

    @app.route('/v1/blob/<blob_id>', methods=['DELETE'])
    def remove_blob(blob_id):
        '''Elimina un blob'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        try:
            BLOB.remove_blob(blob_id, user)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        return make_response('', 204)

    @app.route('/v1/blob/stats/<blob_id>', methods=['GET'])
    def stats_of_blob(blob_id):
        '''Obtener stats de un blob'''
        if BLOB.blob_exists(blob_id):
            return make_response('', 204)
        return make_response(f'Blob #{blob_id} not found', 404)

    @app.route('/v1/blob/<blob_id>/writable_by/<user>', methods=['PUT'])
    def add_write_permissions(blob_id, user):
        '''Otorga permisos de escritura a un usuario'''
        owner = _get_effective_user_(request)
        if not owner:
            return make_response('Unauthorized', 401)

        try:
            BLOB.add_write_permission(blob_id, user)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except AlreadyDoneError:
            return make_response('', 204)
        return make_response(f'User {user} granted with write permissions', 200)

    @app.route('/v1/blob/<blob_id>/readable_by/<user>', methods=['PUT'])
    def add_read_permissions(blob_id, user):
        '''Otorga permisos de lectura a un usuario'''
        owner = _get_effective_user_(request)
        if not owner:
            return make_response('Unauthorized', 401)

        try:
            BLOB.add_read_permission(blob_id, user)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except AlreadyDoneError:
            return make_response('', 204)
        return make_response(f'User {user} granted with read permissions', 200)

    @app.route('/v1/blob/<blob_id>/writable_by/<user>', methods=['DELETE'])
    def remove_write_permissions(blob_id, user):
        '''Elimina permisos de escritura a un usuario'''
        owner = _get_effective_user_(request)
        if not owner:
            return make_response('Unauthorized', 401)

        try:
            BLOB.remove_write_permission(blob_id, user)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except AlreadyDoneError:
            return make_response('', 204)
        return make_response(f'Revoked write permission for user {user}', 200)

    @app.route('/v1/blob/<blob_id>/readable_by/<user>', methods=['DELETE'])
    def remove_read_permissions(blob_id, user):
        '''Elimina permisos de lectura a un usuario'''
        owner = _get_effective_user_(request)
        if not owner:
            return make_response('Unauthorized', 401)

        try:
            BLOB.remove_read_permission(blob_id, user)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except AlreadyDoneError:
            return make_response('', 204)
        return make_response(f'Revoked read permission for user {user}', 200)


class BlobService:
    '''Wrap all components used by the service'''
    def __init__(self, storage_path, auth_service, host='0.0.0.0', port=DEFAULT_BLOB_SERVICE_PORT):
        self._blobdb_ = BlobDB(storage_path)
        self._auth_ = get_AuthService(auth_service)

        self._host_ = host
        self._port_ = port

        self._app_ = Flask(__name__.split('.', maxsplit=1)[0])
        routeApp(self._app_, self._blobdb_, self._auth_)

    @property
    def base_uri(self):
        '''Get the base URI to access the API'''
        host = '127.0.0.1' if self._host_ in ['0.0.0.0'] else self._host_
        return f'http://{host}:{self._port_}'

    def start(self):
        '''Start HTTPD'''
        self._app_.run(host=self._host_, port=self._port_, debug=HTTPS_DEBUG_MODE)

    def stop(self):
        '''Do nothing'''


def main():
    '''Entry point for the auth server'''
    user_options = parse_commandline()
    if not user_options.storage:
        remove_storage = True
        user_options.storage = tempfile.mkdtemp()
    else:
        remove_storage = False

    service = BlobService(
        user_options.storage, user_options.auth_url, user_options.address, user_options.port
    )
    try:
        print(f'Starting service on: {service.base_uri}')
        service.start()
    except Exception as error: # pylint: disable=broad-except
        logging.error('Cannot start API: %s', error)
        sys.exit(1)

    service.stop()
    if remove_storage:
        shutil.rmtree(user_options.storage)

    sys.exit(0)


def parse_commandline():
    '''Parse command line'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('auth_url', type=str, help='Auth service URL')
    parser.add_argument(
        '-p', '--port', type=int, default=DEFAULT_BLOB_SERVICE_PORT,
        help='Listening port (default: %(default)s)', dest='port'
    )
    parser.add_argument(
        '-l', '--listening', type=str, default='0.0.0.0',
        help='Listening address (default: all interfaces)', dest='address'
    )
    parser.add_argument(
        '-s', '--storage', type=str, default=None,
        help='Folder to use as storage (default: temporal folder', dest='storage'
    )
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    main()
