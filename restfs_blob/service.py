#!/usr/bin/env python3

'''
    Implementacion del servicio de almacenamiento de objetos
'''

import os
import os.path
import json
import shutil
import logging
from pathlib import Path

from werkzeug.datastructures import FileStorage

from restfs_common.errors import Unauthorized, ObjectNotFound, AlreadyDoneError, ObjectAlreadyExists
from restfs_common.constants import ADMIN, WRITABLE, READABLE, LOCAL_FILENAME, BLOB_DB_FILENAME,\
    DEFAULT_ENCODING


_WRN = logging.warning


def _initialize_(storage_path):
    '''Create the folder and an empty JSON file'''
    _WRN(f'Initializing new storage folder in: {storage_path}')
    if not os.path.exists(storage_path):
        _WRN('Creating new folder: {storage_path}')
        os.makedirs(storage_path, exist_ok=True)
    db_file = os.path.join(storage_path, BLOB_DB_FILENAME)
    with open(db_file, 'w', encoding=DEFAULT_ENCODING) as contents:
        json.dump({}, contents)


class BlobDB:
    '''
        Controla la base de datos persistente del servicio de almacenamiento de objetos
    '''
    def __init__(self, storage_path):
        if (not os.path.exists(storage_path) or
            not os.path.exists(os.path.join(storage_path, BLOB_DB_FILENAME))):
            _initialize_(storage_path)
        self._storage_root_ = storage_path
        self._db_file_ = os.path.join(storage_path, BLOB_DB_FILENAME)

        self._blobs_ = {}
        self._read_db_()

    def _read_db_(self):
        with open(self._db_file_, 'r', encoding=DEFAULT_ENCODING) as contents:
            self._blobs_ = json.load(contents)

    def _commit_(self):
        with open(self._db_file_, 'w', encoding=DEFAULT_ENCODING) as contents:
            json.dump(self._blobs_, contents, indent=2, sort_keys=True)

    def _store_blob_(self, blob_id, blob_source):
        blob_filename = os.path.join(self._storage_root_, blob_id)
        if isinstance(blob_source, bytes):
            with open(blob_filename, 'wb') as contents:
                contents.write(blob_source)
        elif isinstance(blob_source, (str, Path)):
            if not os.path.exists(blob_source):
                raise ObjectNotFound(f'Blob source "{blob_source}"')
            shutil.copyfile(blob_source, blob_filename)
        elif isinstance(blob_source, FileStorage): # pragma: no cover
            blob_source.save(blob_filename)
        return blob_filename

    def _assert_blob_exists_(self, blob_id):
        if blob_id not in self._blobs_:
            raise ObjectNotFound(f'Blob #{blob_id}')

    def new_blob(self, blob_id, blob_source, owner):
        '''Create new blob'''
        if blob_id in self._blobs_:
            raise ObjectAlreadyExists(f'Blob #{blob_id}')
        owner = [] if owner == ADMIN else [owner]
        local_filename = self._store_blob_(blob_id, blob_source)
        self._blobs_[blob_id] = {
            READABLE: owner,
            WRITABLE: owner,
            LOCAL_FILENAME: local_filename
        }
        self._commit_()
        return blob_id

    def update_blob(self, blob_id, blob_source, user):
        '''Update blob data'''
        self._assert_blob_exists_(blob_id)
        if not self.is_writable_by(blob_id, user):
            raise Unauthorized(user, f'Cannot write Blob #{blob_id}')
        self._blobs_[blob_id][LOCAL_FILENAME] = self._store_blob_(blob_id, blob_source)

    def remove_blob(self, blob_id, user):
        '''Remove blob'''
        self._assert_blob_exists_(blob_id)
        if not self.is_writable_by(blob_id, user):
            raise Unauthorized(user, f'Cannot write Blob #{blob_id}')
        try:
            os.remove(os.path.join(self._storage_root_, blob_id))
        except OSError as error: # pragma: no cover
            _WRN(f'Cannot remove Blob #{blob_id}: {error}')
        del self._blobs_[blob_id]
        self._commit_()

    def add_write_permission(self, blob_id, owner, user):
        '''Allow the given user to write the blob'''
        self._assert_blob_exists_(blob_id)
        if not self.is_writable_by(blob_id, owner):
            raise Unauthorized(owner, f'Cannot write Blob #{blob_id}')
        if self.is_writable_by(blob_id, user):
            raise AlreadyDoneError(f'User "{user}" already with writable permissions')
        self._blobs_[blob_id][WRITABLE].append(user)
        self._commit_()

    def add_read_permission(self, blob_id, owner, user):
        '''Allow the given user to read the blob'''
        self._assert_blob_exists_(blob_id)
        if not self.is_writable_by(blob_id, owner):
            raise Unauthorized(owner, f'Cannot write Blob #{blob_id}')
        if self.is_readable_by(blob_id, user):
            raise AlreadyDoneError(f'User "{user}" already with readable permissions')
        self._blobs_[blob_id][READABLE].append(user)
        self._commit_()

    def remove_write_permission(self, blob_id, owner, user):
        '''Revoke the given user to write the blob'''
        self._assert_blob_exists_(blob_id)
        if user == ADMIN:
            raise ObjectNotFound(f'User "{ADMIN}"')
        if not self.is_writable_by(blob_id, owner):
            raise Unauthorized(owner, f'Cannot write Blob #{blob_id}')
        if self.is_writable_by(blob_id, user):
            self._blobs_[blob_id][WRITABLE].remove(user)
            self._commit_()
            return
        raise AlreadyDoneError(f'User "{user}" already revoked from writable permission')

    def remove_read_permission(self, blob_id, owner, user):
        '''Revoke the given user to read the blob'''
        self._assert_blob_exists_(blob_id)
        if user == ADMIN:
            raise ObjectNotFound(f'User "{ADMIN}"')
        if not self.is_writable_by(blob_id, owner):
            raise Unauthorized(owner, f'Cannot write Blob #{blob_id}')
        if self.is_readable_by(blob_id, user):
            self._blobs_[blob_id][READABLE].remove(user)
            self._commit_()
            return
        raise AlreadyDoneError(f'User "{user}" already revoked from readable permission')

    def is_writable_by(self, blob_id, user):
        '''Return if given blob is writable by the user'''
        self._assert_blob_exists_(blob_id)
        if user == ADMIN:
            return True
        return user in self._blobs_[blob_id][WRITABLE]

    def is_readable_by(self, blob_id, user):
        '''Return if given blob is readable by the user'''
        self._assert_blob_exists_(blob_id)
        if user == ADMIN:
            return True
        return user in self._blobs_[blob_id][READABLE]

    def blob_exists(self, blob_id):
        '''Return if a given blob exists or not'''
        try:
            self._assert_blob_exists_(blob_id)
            return True
        except ObjectNotFound:
            return False

    def blob_local_filename(self, blob_id):
        '''Return the absolute path to a given blob_id'''
        self._assert_blob_exists_(blob_id)
        return self._blobs_[blob_id][LOCAL_FILENAME]
