#!/usr/bin/env python3

import os
import uuid
import shutil
import random
import os.path
import tempfile
import unittest
from pathlib import Path

from restfs_common.errors import Unauthorized, ObjectNotFound, AlreadyDoneError, ObjectAlreadyExists
from restfs_common.constants import BLOB_DB_FILENAME, ADMIN

from restfs_blob.service import BlobDB


USER1 = 'test_user1'
USER2 = 'test_user2'

BLOB_ID = str(uuid.uuid4())
WRONG_BLOB_ID = 'wrong_blob_id'


def _generate_random_bytes_(size=100):
    return random.randbytes(size)


class TestBlobDB(unittest.TestCase):

    def test_creation(self):
        '''Test initialization with folder'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)
            self.assertTrue(os.path.exists(Path(workspace).joinpath(BLOB_DB_FILENAME)))

    def test_creation_withoutfolder(self):
        '''Test initialization without folder'''
        workspace = os.path.join(os.getcwd(), 'tempstorage')
        blobdb = BlobDB(workspace)
        self.assertTrue(os.path.exists(Path(workspace).joinpath(BLOB_DB_FILENAME)))
        shutil.rmtree(workspace)

    def test_blob_creation_from_bytes(self):
        '''Test blob creation from bytes'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            self.assertTrue(os.path.exists(Path(workspace).joinpath(blob_id)))
            self.assertTrue(blobdb.is_readable_by(blob_id, USER1))
            self.assertTrue(blobdb.is_writable_by(blob_id, USER1))
            self.assertFalse(blobdb.is_readable_by(blob_id, USER2))
            self.assertFalse(blobdb.is_writable_by(blob_id, USER2))
            self.assertTrue(blobdb.blob_exists(BLOB_ID))
            self.assertFalse(blobdb.blob_exists(WRONG_BLOB_ID))

    def test_blob_creation_overwrite(self):
        '''Test blob creation overwriting'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(ObjectAlreadyExists):
                blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)

    def test_blob_update_from_bytes(self):
        '''Test blob update from bytes'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            blobdb.update_blob(blob_id, _generate_random_bytes_(), USER1)

    def test_blob_creation_from_file(self):
        '''Test blob creation from file'''
        with tempfile.TemporaryDirectory() as workspace:
            source = os.path.join(workspace, 'blob_source')
            with open(source, 'wb') as contents:
                contents.write(_generate_random_bytes_())

            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, source, USER1)
            self.assertTrue(os.path.exists(Path(workspace).joinpath(blob_id)))
            self.assertTrue(blobdb.is_readable_by(blob_id, ADMIN))
            self.assertTrue(blobdb.is_writable_by(blob_id, ADMIN))
            self.assertTrue(blobdb.is_readable_by(blob_id, USER1))
            self.assertTrue(blobdb.is_writable_by(blob_id, USER1))
            self.assertFalse(blobdb.is_readable_by(blob_id, USER2))
            self.assertFalse(blobdb.is_writable_by(blob_id, USER2))

    def test_blob_update_from_file(self):
        '''Test blob update from source file'''
        with tempfile.TemporaryDirectory() as workspace:
            source = os.path.join(workspace, 'blob_source')
            with open(source, 'wb') as contents:
                contents.write(_generate_random_bytes_())

            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            blobdb.update_blob(blob_id, source, USER1)

    def test_blob_creation_from_not_exists_file(self):
        '''Test blob creation from not exists file'''
        with tempfile.TemporaryDirectory() as workspace:
            source = os.path.join(workspace, 'blob_source')

            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blob_id = blobdb.new_blob(BLOB_ID, source, USER1)

    def test_blob_update_with_wrong_blob_id(self):
        '''Test blob update with wrong blob_id'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blobdb.update_blob(WRONG_BLOB_ID, _generate_random_bytes_(), USER1)

    def test_blob_update_with_wrong_user(self):
        '''Test blob update by wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(Unauthorized):
                blobdb.update_blob(blob_id, _generate_random_bytes_(), USER2)

    def test_remove_blob(self):
        '''Test blob removal'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            blobdb.remove_blob(blob_id, USER1)

    def test_remove_wrong_blob(self):
        '''Test wrong blob removal'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(ObjectNotFound):
                blobdb.remove_blob(WRONG_BLOB_ID, USER1)

    def test_remove_blob_wrong_user(self):
        '''Test blob removal with wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(Unauthorized):
                blobdb.remove_blob(blob_id, USER2)

    def test_grant_writable_access(self):
        '''Test grant writable access to an user'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            self.assertFalse(blobdb.is_writable_by(blob_id, USER2))
            blobdb.add_write_permission(blob_id, USER1, USER2)
            self.assertTrue(blobdb.is_writable_by(blob_id, USER2))

    def test_grant_readable_access(self):
        '''Test grant readable access to an user'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            self.assertFalse(blobdb.is_readable_by(blob_id, USER2))
            blobdb.add_read_permission(blob_id, USER1, USER2)
            self.assertTrue(blobdb.is_readable_by(blob_id, USER2))

    def test_grant_writable_access_wrong_blob(self):
        '''Test grant writable access to an user with wrong blob_id'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blobdb.add_write_permission(WRONG_BLOB_ID, USER1, USER2)

    def test_grant_readable_access_wrong_blob(self):
        '''Test grant readable access to an user with wrong blob_id'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blobdb.add_read_permission(WRONG_BLOB_ID, USER1, USER2)

    def test_grant_writable_access_duplicated_user(self):
        '''Test grant writable access to an user already granted'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            blobdb.add_write_permission(blob_id, USER1, USER2)
            self.assertTrue(blobdb.is_writable_by(blob_id, USER2))
            with self.assertRaises(AlreadyDoneError):
                blobdb.add_write_permission(blob_id, USER1, USER2)

    def test_grant_readable_access_duplicated_user(self):
        '''Test grant readable access to an user already granted'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            blobdb.add_read_permission(blob_id, USER1, USER2)
            self.assertTrue(blobdb.is_readable_by(blob_id, USER2))
            with self.assertRaises(AlreadyDoneError):
                blobdb.add_read_permission(blob_id, USER1, USER2)

    def test_grant_writable_access_wrong_owner(self):
        '''Test grant writable access to an user with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(Unauthorized):
                blobdb.add_write_permission(blob_id, USER2, USER1)

    def test_grant_readable_access_wrong_owner(self):
        '''Test grant readable access to an user with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(Unauthorized):
                blobdb.add_read_permission(blob_id, USER2, USER1)

    def test_revoke_writable_access(self):
        '''Test revoke writable access to an user'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            blobdb.add_write_permission(blob_id, USER1, USER2)
            self.assertTrue(blobdb.is_writable_by(blob_id, USER2))
            blobdb.remove_write_permission(blob_id, USER1, USER2)
            self.assertFalse(blobdb.is_writable_by(blob_id, USER2))

    def test_revoke_readable_access(self):
        '''Test revoke readable access to an user'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            blobdb.add_read_permission(blob_id, USER1, USER2)
            self.assertTrue(blobdb.is_readable_by(blob_id, USER2))
            blobdb.remove_read_permission(blob_id, USER1, USER2)
            self.assertFalse(blobdb.is_readable_by(blob_id, USER2))

    def test_revoke_writable_access_to_admin(self):
        '''Test revoke writable access to the admin'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            self.assertTrue(blobdb.is_writable_by(blob_id, ADMIN))
            with self.assertRaises(ObjectNotFound):
                blobdb.remove_write_permission(blob_id, USER1, ADMIN)

    def test_revoke_readable_access_to_admin(self):
        '''Test revoke readable access to the admin'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            self.assertTrue(blobdb.is_readable_by(blob_id, ADMIN))
            with self.assertRaises(ObjectNotFound):
                blobdb.remove_read_permission(blob_id, USER1, ADMIN)

    def test_revoke_writable_access_wrong_blob(self):
        '''Test revoke writable access to an user with wrong blob_id'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blobdb.remove_write_permission(WRONG_BLOB_ID, USER1, USER2)

    def test_revoke_readable_access_wrong_blob(self):
        '''Test revoke readable access to an user with wrong blob_id'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blobdb.remove_read_permission(WRONG_BLOB_ID, USER1, USER2)

    def test_revoke_writable_access_non_authorized_user(self):
        '''Test revoke writable access to an user already revoked'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(AlreadyDoneError):
                blobdb.remove_write_permission(blob_id, USER1, USER2)

    def test_revoke_readable_access_duplicated_user(self):
        '''Test revoke readable access to an user already revoked'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(AlreadyDoneError):
                blobdb.remove_read_permission(blob_id, USER1, USER2)

    def test_revoke_writable_access_wrong_owner(self):
        '''Test revoke writable access to an user already granted'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(Unauthorized):
                blobdb.remove_write_permission(blob_id, USER2, USER1)

    def test_revoke_readable_access_wrong_owner(self):
        '''Test revoke readable access to an user already granted'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            with self.assertRaises(Unauthorized):
                blobdb.remove_read_permission(blob_id, USER2, USER1)

    def test_check_writable_access_wrong_blob_id(self):
        '''Test revoke writable access to an user already revoked'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blobdb.is_writable_by(WRONG_BLOB_ID, USER1)

    def test_check_readable_access_wrong_blob_id(self):
        '''Test revoke readable access to an user already revoked'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)

            with self.assertRaises(ObjectNotFound):
                blobdb.is_readable_by(WRONG_BLOB_ID, USER1)

    def test_get_local_filename(self):
        '''Test access to local filename'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)
            blob_id = blobdb.new_blob(BLOB_ID, _generate_random_bytes_(), USER1)
            self.assertTrue(os.path.exists(blobdb.blob_local_filename(blob_id)))

    def test_get_local_filename_wrong_blob_id(self):
        '''Test access to local filename'''
        with tempfile.TemporaryDirectory() as workspace:
            blobdb = BlobDB(workspace)
            with self.assertRaises(ObjectNotFound):
                blobdb.blob_local_filename(BLOB_ID)
