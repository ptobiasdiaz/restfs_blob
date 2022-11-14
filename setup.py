#!/usr/bin/env python3

'''Ejemplo de API REST para ADI'''

from setuptools import setup

setup(
    name='restfs-blob',
    version='0.1',
    description=__doc__,
    packages=['restfs_blob'],
    entry_points={
        'console_scripts': [
            'blob_service=restfs_blob.server:main'
        ]
    }
)