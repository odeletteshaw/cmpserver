# coding: utf-8
"""cmp-mock-server — a CMP (RFC 4210) CA simulator with field-level mocking.

The simulator acts as a Certificate Authority over HTTP: it receives ``ir`` /
``kur`` / ``certconf`` from a client (EE) and replies with ``ip`` /
``kup`` / ``pkiconf``. Its core feature is a field-level mock injector that
can tamper with any response field *before* signing, to verify that the EE
correctly rejects malformed certificate responses.
"""

from cmp_mock_server.cmpbuilder import (
    CMPConfirmBuilder,
    CMPErrorBuilder,
    CMPResponseBuilder,
    MockSpec,
    OMIT,
    Raw,
    general_name,
)
from cmp_mock_server.controllers.cmp_server import CmpServer
from cmp_mock_server.scripts.ca import create_root_cert, issue_end_entity

__version__ = '0.2.0'

__all__ = [
    'CMPResponseBuilder',
    'CMPConfirmBuilder',
    'CMPErrorBuilder',
    'MockSpec',
    'OMIT',
    'Raw',
    'general_name',
    'CmpServer',
    'create_root_cert',
    'issue_end_entity',
    '__version__',
]
