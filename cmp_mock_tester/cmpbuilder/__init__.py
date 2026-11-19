# coding: utf-8
"""
CMP 报文构建器（仅 CA -> EE 发送侧 + error）。

本模块只构建 CA 主动发出的报文；ir / kur / certconf 是从 EE 收进来、
用 PKIMessage.load 解析的，不在此构建。

  CA  -> EE  :  ip       CMPResponseBuilder('ip', ...).build()
  CA  -> EE  :  kup      CMPResponseBuilder('kup', ...).build()
  CA  -> EE  :  pkiconf  CMPConfirmBuilder('pkiconf', ...).build()
  any -> peer:  error    CMPErrorBuilder(...).build()
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import inspect
import re
import sys
import textwrap

from asn1crypto import x509, keys, core
from asn1crypto.util import timezone
from oscrypto import asymmetric, util

from cmp_mock_tester.asn1crypto_cmp.rfc4210 import *

from .cmp_mock import _corrupt_bytes, MockSpec, OMIT, Raw, general_name

if sys.version_info < (3,):
    int_types = (int, long)  # noqa
    str_cls = unicode  # noqa
    byte_cls = str
else:
    int_types = (int,)
    str_cls = str
    byte_cls = bytes

__all__ = [
    'CMPResponseBuilder',
    'CMPConfirmBuilder',
    'CMPErrorBuilder',
    # re-exported from .cmp_mock for convenience
    'MockSpec',
    'OMIT',
    'Raw',
    'general_name',
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _writer(func):
    """Decorator for a custom writer with a default reader."""
    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)


class _ProtectedPart(core.Sequence):
    """
    ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody }

    PKIProtection is computed over DER(ProtectedPart).  Both the header
    (which already carries protection_alg) and the body must be fully built
    before calling .dump().
    """
    _fields = [
        ('header', PKIHeader),
        ('body', PKIBody),
    ]


def _load_signing_key(value):
    """Ensures we have an oscrypto PrivateKey, loading it if necessary."""
    if isinstance(value, asymmetric.PrivateKey):
        return value
    if isinstance(value, keys.PrivateKeyInfo):
        return asymmetric.load_private_key(value)
    raise TypeError(_pretty_message(
        '''
        signing_private_key must be an asn1crypto.keys.PrivateKeyInfo or
        oscrypto.asymmetric.PrivateKey, not %s
        ''',
        _type_name(value)
    ))


def _load_certificate(value):
    """Ensures we have an asn1crypto Certificate."""
    if isinstance(value, asymmetric.Certificate):
        return value.asn1
    if isinstance(value, x509.Certificate):
        return value
    raise TypeError(_pretty_message(
        '''
        certificate must be an asn1crypto.x509.Certificate or
        oscrypto.asymmetric.Certificate, not %s
        ''',
        _type_name(value)
    ))


def _signature_alg_id(private_key, hash_algo):
    """Returns the algorithm string used in SignedDigestAlgorithm."""
    algo = private_key.algorithm
    if algo == 'ec':
        algo = 'ecdsa'
    return '%s_%s' % (hash_algo, algo)


def _sign(private_key, data, hash_algo):
    """Signs *data* and returns raw signature bytes."""
    if private_key.algorithm == 'rsa':
        return asymmetric.rsa_pkcs1v15_sign(private_key, data, hash_algo)
    elif private_key.algorithm == 'dsa':
        return asymmetric.dsa_sign(private_key, data, hash_algo)
    elif private_key.algorithm == 'ec':
        return asymmetric.ecdsa_sign(private_key, data, hash_algo)
    raise ValueError('Unsupported key algorithm: %s' % private_key.algorithm)


def _build_header(sender, recipient, transaction_id, sender_nonce,
                  recip_nonce=None, protection_alg_id=None, sender_kid=None):
    """
    Assembles a PKIHeader from already-resolved values.

    :return:
        A PKIHeader object
    """
    fields = {
        'pvno': 'cmp2000',
        'sender': sender,
        'recipient': recipient,
        'message_time': datetime.now(timezone.utc),
        'transaction_id': transaction_id,
        'sender_nonce': sender_nonce,
    }
    if recip_nonce is not None:
        fields['recip_nonce'] = recip_nonce
    if protection_alg_id is not None:
        fields['protection_alg'] = {'algorithm': protection_alg_id}
    if sender_kid is not None:
        fields['sender_kid'] = sender_kid
    return PKIHeader(fields)


def _assemble_message(header, body_name, body_value,
                      private_key=None, hash_algo=None,
                      signing_certificate=None, mock=None):
    """
    Wraps header + body into a PKIMessage, computing PKIProtection if a
    private key is provided.

    Protection is computed over DER(_ProtectedPart{header, body}) as
    required by RFC 4210 Section 5.1.3.

    mock (cmp_mock.MockSpec | None): field-level injection for negative
    testing.  Order is fixed:
      1. pre-protection content injection (header / body) -> signature
         covers the tampered content
      2. protection knob (normal / skip / wrong_key / corrupt / empty)
      3. extra_certs (mock overrides the extraCerts_flag behaviour)

    :return:
        A PKIMessage object
    """
    # 1) pre-protection content injection
    if mock is not None:
        mock.apply_pre_protection(header, body_value)

    body = PKIBody(name=body_name, value=body_value)

    msg_fields = {'header': header, 'body': body}

    # 2) protection knob
    prot_mode = mock.protection if mock is not None else 'normal'
    if private_key is not None and prot_mode != 'skip':
        sign_key = private_key
        if prot_mode == 'wrong_key' and mock is not None and mock.protection_key is not None:
            sign_key = _load_signing_key(mock.protection_key)
        protected_part = _ProtectedPart({'header': header, 'body': body})
        sig_bytes = _sign(sign_key, protected_part.dump(), hash_algo)
        if prot_mode == 'corrupt':
            sig_bytes = _corrupt_bytes(sig_bytes)
        elif prot_mode == 'empty':
            sig_bytes = b''
        msg_fields['protection'] = sig_bytes

    # 3) extra_certs: mock takes precedence, else legacy signing_certificate
    if mock is not None:
        certs = mock.resolve_extra_certs(signing_certificate)
    else:
        certs = [signing_certificate] if signing_certificate is not None else None
    if certs:
        msg_fields['extra_certs'] = CMPCertificates(certs)

    return PKIMessage(msg_fields)


def _coerce_general_name(value, param_name):
    """
    Accepts a GeneralName, Name, or Certificate and always returns a
    GeneralName(directory_name=...).
    """
    if isinstance(value, x509.Certificate):
        return x509.GeneralName(name='directory_name', value=value.subject)
    if isinstance(value, x509.Name):
        return x509.GeneralName(name='directory_name', value=value)
    if isinstance(value, x509.GeneralName):
        return value
    raise TypeError(_pretty_message(
        '''
        %s must be an asn1crypto.x509.GeneralName, x509.Name, or
        x509.Certificate, not %s
        ''',
        param_name,
        _type_name(value)
    ))


# ---------------------------------------------------------------------------
# CMPResponseBuilder  (ip / kup)
# ---------------------------------------------------------------------------

class CMPResponseBuilder(object):
    """
    Builds an ip (Initialization Response) or kup (Key Update Response).

    The CA calls add_accepted() or add_rejected() once per certificate
    request in the matching ir/kur, then calls build() to sign and return
    the PKIMessage.
    """

    _message_type = None
    _sender = None
    _recipient = None
    _transaction_id = None
    _sender_nonce = None
    _recip_nonce = None
    _hash_algo = None
    _ca_pubs = None
    _responses = None

    def __init__(self, message_type, sender, recipient):
        """
        :param message_type: A unicode string – "ip" or "kup"
        :param sender:        CA identity (GeneralName / Name / Certificate)
        :param recipient:     EE identity (GeneralName / Name / Certificate)
        """
        if message_type not in ('ip', 'kup'):
            raise ValueError(_pretty_message(
                '''
                message_type must be "ip" or "kup", not %s
                ''',
                repr(message_type)
            ))

        self._message_type = message_type
        self._hash_algo = 'sha256'
        self._responses = []

        self.sender = sender
        self.recipient = recipient

    @_writer
    def sender(self, value):
        self._sender = _coerce_general_name(value, 'sender')

    @_writer
    def recipient(self, value):
        self._recipient = _coerce_general_name(value, 'recipient')

    @_writer
    def transaction_id(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                transaction_id must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._transaction_id = value

    @_writer
    def sender_nonce(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                sender_nonce must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._sender_nonce = value

    @_writer
    def recip_nonce(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                recip_nonce must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._recip_nonce = value

    @_writer
    def hash_algo(self, value):
        if value not in ('sha1', 'sha256', 'sha512'):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))
        self._hash_algo = value

    def set_from_request(self, request_message):
        """
        Copies transaction_id and flips nonces from an incoming ir/kur
        PKIMessage so the caller does not have to do it manually.
        """
        hdr = request_message['header']
        self._transaction_id = hdr['transaction_id']
        self._recip_nonce = hdr['sender_nonce']

    def add_accepted(self, cert_req_id, certificate):
        """
        Adds a successful certificate issuance to the response.

        :param cert_req_id: integer matching the CertRequest's cert_req_id
        :param certificate: the asn1crypto / oscrypto Certificate just signed
        """
        if not isinstance(cert_req_id, int_types):
            raise TypeError(_pretty_message(
                '''
                cert_req_id must be an integer, not %s
                ''',
                _type_name(cert_req_id)
            ))

        certificate = _load_certificate(certificate)

        self._responses.append(CertResponse({
            'cert_req_id': cert_req_id,
            'status': PKIStatusInfo({'status': 'accepted'}),
            'certified_key_pair': CertifiedKeyPair({
                'cert_or_enc_cert': CertOrEncCert(
                    name='certificate',
                    value=certificate
                )
            })
        }))

    def add_rejected(self, cert_req_id, failure_info=None, status_string=None):
        """
        Adds a rejected certificate request to the response.

        :param cert_req_id:  integer matching the CertRequest's cert_req_id
        :param failure_info: optional PKIFailureInfo name, or a set of names
        :param status_string: optional human-readable reason
        """
        if not isinstance(cert_req_id, int_types):
            raise TypeError(_pretty_message(
                '''
                cert_req_id must be an integer, not %s
                ''',
                _type_name(cert_req_id)
            ))

        status_fields = {'status': 'rejection'}
        if failure_info is not None:
            if isinstance(failure_info, str_cls):
                failure_info = set([failure_info])
            status_fields['fail_info'] = PKIFailureInfo(failure_info)
        if status_string is not None:
            status_fields['status_string'] = PKIFreeText([status_string])

        self._responses.append(CertResponse({
            'cert_req_id': cert_req_id,
            'status': PKIStatusInfo(status_fields),
        }))

    def build(self, signing_private_key, signing_certificate, cmp_config):
        """
        Validates, constructs and signs the ip / kup PKIMessage.

        :param signing_private_key: CA private key (PrivateKeyInfo / oscrypto)
        :param signing_certificate: CA certificate (Certificate / oscrypto)
        :param cmp_config:          the CmpServer instance (carries .mock for
                                    field-level injection)
        :return: an asn1crypto PKIMessage
        """
        if not self._responses:
            raise ValueError(_pretty_message(
                '''
                At least one response must be added via add_accepted() or
                add_rejected() before calling build()
                '''
            ))

        priv_key = _load_signing_key(signing_private_key)
        sign_cert = _load_certificate(signing_certificate)

        body_value = CertRepMessage({
            'ca_pubs': CMPCertificates([sign_cert]),
            'response': CertResponses(self._responses)
        })

        if self._transaction_id is None:
            self._transaction_id = util.rand_bytes(16)
        if self._sender_nonce is None:
            self._sender_nonce = util.rand_bytes(16)

        prot_alg_id = _signature_alg_id(priv_key, self._hash_algo)
        sender_kid = sign_cert.key_identifier

        header = _build_header(
            sender=self._sender,
            recipient=self._recipient,
            transaction_id=self._transaction_id,
            sender_nonce=self._sender_nonce,
            recip_nonce=self._recip_nonce,
            protection_alg_id=prot_alg_id,
            sender_kid=sender_kid,
        )

        return _assemble_message(
            header=header,
            body_name=self._message_type,
            body_value=body_value,
            private_key=priv_key,
            hash_algo=self._hash_algo,
            signing_certificate=sign_cert,
            mock=getattr(cmp_config, 'mock', None),
        )


# ---------------------------------------------------------------------------
# CMPConfirmBuilder  (pkiconf)
# ---------------------------------------------------------------------------

class CMPConfirmBuilder(object):
    """
    Builds a pkiconf (PKI Confirmation) – the CA's final acknowledgement
    that the exchange is complete.  Its body is simply Null.

    (certconf is sent by the EE, never built here.)
    """

    _message_type = None
    _sender = None
    _recipient = None
    _transaction_id = None
    _sender_nonce = None
    _recip_nonce = None
    _hash_algo = None

    def __init__(self, message_type, sender, recipient):
        """
        :param message_type: A unicode string – must be "pkiconf"
        :param sender:        CA identity (GeneralName / Name / Certificate)
        :param recipient:     EE identity (GeneralName / Name / Certificate)
        """
        if message_type != 'pkiconf':
            raise ValueError(_pretty_message(
                '''
                message_type must be "pkiconf", not %s
                ''',
                repr(message_type)
            ))

        self._message_type = message_type
        self._hash_algo = 'sha256'

        self.sender = sender
        self.recipient = recipient

    @_writer
    def sender(self, value):
        self._sender = _coerce_general_name(value, 'sender')

    @_writer
    def recipient(self, value):
        self._recipient = _coerce_general_name(value, 'recipient')

    @_writer
    def transaction_id(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                transaction_id must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._transaction_id = value

    @_writer
    def sender_nonce(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                sender_nonce must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._sender_nonce = value

    @_writer
    def recip_nonce(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                recip_nonce must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._recip_nonce = value

    @_writer
    def hash_algo(self, value):
        if value not in ('sha1', 'sha256', 'sha512'):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))
        self._hash_algo = value

    def set_from_response(self, response_message):
        """
        Copies transaction_id and flips nonces from the incoming certconf
        (or ip/kup) PKIMessage being acknowledged.
        """
        hdr = response_message['header']
        self._transaction_id = hdr['transaction_id'].contents
        self._recip_nonce = hdr['sender_nonce'].contents

    def build(self, cmp_config, signing_private_key=None, signing_certificate=None):
        """
        Constructs the pkiconf PKIMessage (Null body).

        :param cmp_config:          the CmpServer instance (carries .mock for
                                    field-level injection)
        :param signing_private_key: CA private key; protection is optional
        :param signing_certificate: CA certificate (required if key given)
        :return: an asn1crypto PKIMessage
        """
        priv_key = _load_signing_key(signing_private_key) if signing_private_key else None
        sign_cert = _load_certificate(signing_certificate) if signing_certificate else None

        # pkiconf body is NULL
        body_value = core.Null()

        if self._transaction_id is None:
            self._transaction_id = util.rand_bytes(16)
        if self._sender_nonce is None:
            self._sender_nonce = util.rand_bytes(16)

        prot_alg_id = None
        sender_kid = None
        if priv_key is not None and sign_cert is not None:
            prot_alg_id = _signature_alg_id(priv_key, self._hash_algo)
            sender_kid = sign_cert.key_identifier

        header = _build_header(
            sender=self._sender,
            recipient=self._recipient,
            transaction_id=self._transaction_id,
            sender_nonce=self._sender_nonce,
            recip_nonce=self._recip_nonce,
            protection_alg_id=prot_alg_id,
            sender_kid=sender_kid,
        )

        return _assemble_message(
            header=header,
            body_name=self._message_type,
            body_value=body_value,
            private_key=priv_key,
            hash_algo=self._hash_algo,
            signing_certificate=sign_cert,
            mock=getattr(cmp_config, 'mock', None),
        )


# ---------------------------------------------------------------------------
# CMPErrorBuilder  (error)
# ---------------------------------------------------------------------------

class CMPErrorBuilder(object):
    """
    Builds an error PKIMessage.  Either side may send one at any point to
    signal that something went wrong.
    """

    _sender = None
    _recipient = None
    _transaction_id = None
    _sender_nonce = None
    _recip_nonce = None
    _hash_algo = None
    _pki_status = None
    _failure_info = None
    _status_string = None
    _error_code = None
    _error_details = None

    def __init__(self, sender, recipient, pki_status, failure_info=None, status_string=None):
        """
        :param sender:        GeneralName / Name / Certificate
        :param recipient:     GeneralName / Name / Certificate
        :param pki_status:    a PKIStatus name, typically "rejection"/"waiting"
        :param failure_info:  optional PKIFailureInfo name
        :param status_string: optional human-readable description
        """
        self._hash_algo = 'sha256'

        self.sender = sender
        self.recipient = recipient
        self.pki_status = pki_status

        if failure_info is not None:
            self.failure_info = failure_info
        if status_string is not None:
            self.status_string = status_string

    @_writer
    def sender(self, value):
        self._sender = _coerce_general_name(value, 'sender')

    @_writer
    def recipient(self, value):
        self._recipient = _coerce_general_name(value, 'recipient')

    @_writer
    def transaction_id(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                transaction_id must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._transaction_id = value

    @_writer
    def sender_nonce(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                sender_nonce must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._sender_nonce = value

    @_writer
    def recip_nonce(self, value):
        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                recip_nonce must be a byte string, not %s
                ''',
                _type_name(value)
            ))
        self._recip_nonce = value

    @_writer
    def hash_algo(self, value):
        if value not in ('sha1', 'sha256', 'sha512'):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))
        self._hash_algo = value

    @_writer
    def pki_status(self, value):
        valid = {
            'accepted', 'granted_with_mods', 'rejection', 'waiting',
            'revocation_warning', 'revocation_notification', 'key_update_warning',
        }
        if not isinstance(value, str_cls) or value not in valid:
            raise ValueError(_pretty_message(
                '''
                pki_status must be one of %s, not %s
                ''',
                ', '.join('"%s"' % s for s in sorted(valid)),
                repr(value)
            ))
        self._pki_status = value

    @_writer
    def failure_info(self, value):
        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                failure_info must be a unicode string, not %s
                ''',
                _type_name(value)
            ))
        self._failure_info = value

    @_writer
    def status_string(self, value):
        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                status_string must be a unicode string, not %s
                ''',
                _type_name(value)
            ))
        self._status_string = value

    @_writer
    def error_code(self, value):
        if not isinstance(value, int_types):
            raise TypeError(_pretty_message(
                '''
                error_code must be an integer, not %s
                ''',
                _type_name(value)
            ))
        self._error_code = value

    @_writer
    def error_details(self, value):
        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                error_details must be a unicode string, not %s
                ''',
                _type_name(value)
            ))
        self._error_details = value

    def build(self, signing_private_key=None, signing_certificate=None):
        """
        Constructs the error PKIMessage.  Signing is optional.
        """
        priv_key = _load_signing_key(signing_private_key) if signing_private_key else None
        sign_cert = _load_certificate(signing_certificate) if signing_certificate else None

        status_fields = {'status': self._pki_status}
        if self._failure_info is not None:
            status_fields['fail_info'] = PKIFailureInfo(set([self._failure_info]))
        if self._status_string is not None:
            status_fields['status_string'] = PKIFreeText([self._status_string])

        error_fields = {
            'pki_status_info': PKIStatusInfo(status_fields),
        }
        if self._error_code is not None:
            error_fields['error_code'] = self._error_code
        if self._error_details is not None:
            error_fields['error_details'] = PKIFreeText([self._error_details])

        body_value = ErrorMsgContent(error_fields)

        if self._transaction_id is None:
            self._transaction_id = util.rand_bytes(16)
        if self._sender_nonce is None:
            self._sender_nonce = util.rand_bytes(16)

        prot_alg_id = None
        sender_kid = None
        if priv_key is not None and sign_cert is not None:
            prot_alg_id = _signature_alg_id(priv_key, self._hash_algo)
            sender_kid = sign_cert.key_identifier

        header = _build_header(
            sender=self._sender,
            recipient=self._recipient,
            transaction_id=self._transaction_id,
            sender_nonce=self._sender_nonce,
            recip_nonce=self._recip_nonce,
            protection_alg_id=prot_alg_id,
            sender_kid=sender_kid,
        )

        return _assemble_message(
            header=header,
            body_name='error',
            body_value=body_value,
            private_key=priv_key,
            hash_algo=self._hash_algo,
            signing_certificate=sign_cert,
        )


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _pretty_message(string, *params):
    output = textwrap.dedent(string)
    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)
    if params:
        output = output % params
    return output.strip()


def _type_name(value):
    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)
