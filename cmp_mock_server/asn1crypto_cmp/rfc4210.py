from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto.algos import SignedDigestAlgorithm
from asn1crypto.core import (
    Any,
    BitString,
    Choice,
    GeneralizedTime,
    Integer,
    Null,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    Sequence,
    SequenceOf,
    UTF8String,
)
from asn1crypto.keys import PublicKeyInfo
from asn1crypto.x509 import Certificate, Extensions, GeneralName, Name


class CMPVersion(Integer):
    _map = {
        1: 'cmp1999',
        2: 'cmp2000',
    }


class PKIFreeText(SequenceOf):
    """One or more human-readable UTF-8 strings."""
    _child_spec = UTF8String


class PKIStatus(Integer):
    _map = {
        0: 'accepted',
        1: 'granted_with_mods',
        2: 'rejection',
        3: 'waiting',
        4: 'revocation_warning',
        5: 'revocation_notification',
        6: 'key_update_warning',
    }


class PKIFailureInfo(BitString):
    _map = {
        0: 'bad_alg',
        1: 'bad_message_check',
        2: 'bad_request',
        3: 'bad_time',
        4: 'bad_cert_id',
        5: 'bad_data_format',
        6: 'wrong_authority',
        7: 'incorrect_data',
        8: 'missing_time_stamp',
        9: 'bad_pop',
        10: 'cert_revoked',
        11: 'cert_confirmed',
        12: 'wrong_integrity',
        13: 'bad_recipient_nonce',
        14: 'time_not_available',
        15: 'unaccepted_policy',
        16: 'unaccepted_extension',
        17: 'add_info_not_available',
        18: 'bad_sender_nonce',
        19: 'bad_cert_template',
        20: 'signer_not_trusted',
        21: 'transaction_id_in_use',
        22: 'unsupported_version',
        23: 'not_authorized',
        24: 'system_unavail',
        25: 'system_failure',
        26: 'duplicate_cert_req',
    }


class PKIStatusInfo(Sequence):
    _fields = [
        ('status', PKIStatus),
        ('status_string', PKIFreeText, {'optional': True}),
        ('fail_info', PKIFailureInfo, {'optional': True}),
    ]


class KeyIdentifier(OctetString):
    """Identifies a key (typically SHA-1 of the SubjectPublicKeyInfo)."""


class CMPCertificate(Certificate):
    """An X.509 v3 certificate as used inside CMP messages."""


class CMPCertificates(SequenceOf):
    _child_spec = Certificate


# ---------------------------------------------------------------------------
# CRMF (RFC 4211) – CertTemplate
# ---------------------------------------------------------------------------

class CertTemplateVersion(Integer):
    _map = {0: 'v1', 1: 'v2', 2: 'v3'}


class OptionalValidity(Sequence):
    _fields = [
        ('not_before', GeneralizedTime, {'implicit': 0, 'optional': True}),
        ('not_after', GeneralizedTime, {'implicit': 1, 'optional': True}),
    ]


class CertTemplate(Sequence):
    """
    A partially-filled certificate template describing what the requester
    wants the issued certificate to contain (RFC 4211 Section 5).
    """
    _fields = [
        ('version', CertTemplateVersion, {'implicit': 0, 'optional': True}),
        ('serial_number', Integer, {'implicit': 1, 'optional': True}),
        ('signing_alg', SignedDigestAlgorithm, {'implicit': 2, 'optional': True}),
        ('issuer', Name, {'explicit': 3, 'optional': True}),
        ('validity', OptionalValidity, {'implicit': 4, 'optional': True}),
        ('subject', Name, {'explicit': 5, 'optional': True}),
        ('public_key', PublicKeyInfo, {'implicit': 6, 'optional': True}),
        ('issuer_uid', OctetBitString, {'implicit': 7, 'optional': True}),
        ('subject_uid', OctetBitString, {'implicit': 8, 'optional': True}),
        ('extensions', Extensions, {'implicit': 9, 'optional': True}),
    ]


# ---------------------------------------------------------------------------
# CRMF – Controls
# ---------------------------------------------------------------------------

class AttributeTypeAndValue(Sequence):
    _fields = [
        ('type', ObjectIdentifier),
        ('value', Any),
    ]


class Controls(SequenceOf):
    _child_spec = AttributeTypeAndValue


class RegInfos(SequenceOf):
    _child_spec = AttributeTypeAndValue


# ---------------------------------------------------------------------------
# CRMF – Proof of Possession (POP)
# ---------------------------------------------------------------------------

class SubsequentMessage(Integer):
    _map = {0: 'encr_cert', 1: 'challenge_resp'}


class POPOPrivKey(Choice):
    _alternatives = [
        ('this_message', OctetBitString, {'implicit': 0}),
        ('subsequent_message', SubsequentMessage, {'implicit': 1}),
        ('dh_mac_value', OctetBitString, {'implicit': 2}),
        ('agree_mac', OctetString, {'implicit': 3}),
        ('encrypted_key', OctetString, {'implicit': 4}),
    ]


class POPOSigningKey(Sequence):
    _fields = [
        ('algorithm_identifier', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class ProofOfPossession(Choice):
    _alternatives = [
        ('ra_verified', Null, {'implicit': 0}),
        ('signature', POPOSigningKey, {'implicit': 1}),
        ('key_encipherment', POPOPrivKey, {'implicit': 2}),
        ('key_agreement', POPOPrivKey, {'implicit': 3}),
    ]


# ---------------------------------------------------------------------------
# CRMF – CertRequest / CertReqMessages  (ir and kur share this type)
# ---------------------------------------------------------------------------

class CertRequest(Sequence):
    _fields = [
        ('cert_req_id', Integer),
        ('cert_template', CertTemplate),
        ('controls', Controls, {'optional': True}),
    ]


class CertReqMsg(Sequence):
    _fields = [
        ('cert_req', CertRequest),
        ('pop', ProofOfPossession, {'optional': True}),
        ('reg_info', RegInfos, {'optional': True}),
    ]


class CertReqMessages(SequenceOf):
    """Payload for ir (tag 0) and kur (tag 7)."""
    _child_spec = CertReqMsg


# ---------------------------------------------------------------------------
# Encrypted cert / key structures  (carried inside ip / kup responses)
# ---------------------------------------------------------------------------

class EncryptedValue(Sequence):
    _fields = [
        ('int_key_alg', SignedDigestAlgorithm, {'implicit': 0, 'optional': True}),
        ('sym_alg', SignedDigestAlgorithm, {'implicit': 1, 'optional': True}),
        ('enc_sym_key', OctetBitString, {'implicit': 2, 'optional': True}),
        ('key_alg', SignedDigestAlgorithm, {'implicit': 3, 'optional': True}),
        ('value_hint', OctetString, {'implicit': 4, 'optional': True}),
        ('enc_value', OctetBitString),
    ]


class CertOrEncCert(Choice):
    _alternatives = [
        ('certificate', Certificate, {'explicit': 0}),
        ('encrypted_cert', EncryptedValue, {'explicit': 1}),
    ]


class SinglePubInfo(Sequence):
    _fields = [
        ('pub_method', Integer),
        ('pub_location', GeneralName, {'optional': True}),
    ]


class SinglePubInfos(SequenceOf):
    _child_spec = SinglePubInfo


class PKIPublicationInfo(Sequence):
    _fields = [
        ('action', Integer),
        ('pub_infos', SinglePubInfos, {'optional': True}),
    ]


class CertifiedKeyPair(Sequence):
    _fields = [
        ('cert_or_enc_cert', CertOrEncCert),
        ('private_key', EncryptedValue, {'explicit': 0, 'optional': True}),
        ('publication_info', PKIPublicationInfo, {'explicit': 1, 'optional': True}),
    ]


# ---------------------------------------------------------------------------
# CertRepMessage  (ip / kup share this type)
# ---------------------------------------------------------------------------

class CertResponse(Sequence):
    _fields = [
        ('cert_req_id', Integer),
        ('status', PKIStatusInfo),
        ('certified_key_pair', CertifiedKeyPair, {'optional': True}),
        ('rsp_info', OctetString, {'optional': True}),
    ]


class CertResponses(SequenceOf):
    _child_spec = CertResponse


class CertRepMessage(Sequence):
    """Payload for ip (tag 1) and kup (tag 8)."""
    _fields = [
        ('ca_pubs', CMPCertificates, {'explicit': 1, 'optional': True}),
        ('response', CertResponses),
    ]


# ---------------------------------------------------------------------------
# ErrorMsgContent  (error, tag 23)
# ---------------------------------------------------------------------------

class ErrorMsgContent(Sequence):
    _fields = [
        ('pki_status_info', PKIStatusInfo),
        ('error_code', Integer, {'optional': True}),
        ('error_details', PKIFreeText, {'optional': True}),
    ]


# ---------------------------------------------------------------------------
# CertConfirmContent  (certconf, tag 24)
# ---------------------------------------------------------------------------

class CertStatus(Sequence):
    """
    Sent by the EE to confirm receipt of a certificate.
    cert_hash is a hash of the DER-encoded certificate body.
    """
    _fields = [
        ('cert_hash', OctetString),
        ('cert_req_id', Integer),
        ('status_info', PKIStatusInfo, {'optional': True}),
    ]


class CertConfirmContent(SequenceOf):
    _child_spec = CertStatus


# ---------------------------------------------------------------------------
# GeneralInfo  (optional header extension entries)
# ---------------------------------------------------------------------------

class InfoTypeId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.4.13': 'implicit_confirm',
        '1.3.6.1.5.5.7.4.14': 'confirm_wait_time',
        '1.3.6.1.5.5.7.4.16': 'supported_language_tags',
    }


class InfoTypeAndValue(Sequence):
    _fields = [
        ('info_type', InfoTypeId),
        ('info_value', Any, {'optional': True}),
    ]


class GeneralInfos(SequenceOf):
    _child_spec = InfoTypeAndValue


# ---------------------------------------------------------------------------
# PKIHeader
# ---------------------------------------------------------------------------

class PKIHeader(Sequence):
    """
    Routing and protection metadata carried in every PKIMessage
    (RFC 4210 Section 5.1.1).
    """
    _fields = [
        ('pvno', CMPVersion),
        ('sender', GeneralName),
        ('recipient', GeneralName),
        ('message_time', GeneralizedTime, {'explicit': 0, 'optional': True}),
        ('protection_alg', SignedDigestAlgorithm, {'explicit': 1, 'optional': True}),
        ('sender_kid', KeyIdentifier, {'explicit': 2, 'optional': True}),
        ('recip_kid', KeyIdentifier, {'explicit': 3, 'optional': True}),
        ('transaction_id', OctetString, {'explicit': 4, 'optional': True}),
        ('sender_nonce', OctetString, {'explicit': 5, 'optional': True}),
        ('recip_nonce', OctetString, {'explicit': 6, 'optional': True}),
        ('free_text', PKIFreeText, {'explicit': 7, 'optional': True}),
        ('general_info', GeneralInfos, {'explicit': 8, 'optional': True}),
    ]


# ---------------------------------------------------------------------------
# PKIBody  (only the 7 required alternatives)
# ---------------------------------------------------------------------------

class PKIBody(Choice):
    """
    Discriminated union carrying exactly one CMP message payload.
    Tag numbers match RFC 4210 Section 5.1.2.
    """
    _alternatives = [
        ('ir', CertReqMessages, {'explicit': 0}),    # Initialization Request
        ('ip', CertRepMessage, {'explicit': 1}),     # Initialization Response
        ('kur', CertReqMessages, {'explicit': 7}),   # Key Update Request
        ('kup', CertRepMessage, {'explicit': 8}),    # Key Update Response
        ('pkiconf', Null, {'explicit': 19}),         # PKI Confirmation
        ('error', ErrorMsgContent, {'explicit': 23}),       # Error Message
        ('certconf', CertConfirmContent, {'explicit': 24}),  # Certificate Confirmation
    ]


# ---------------------------------------------------------------------------
# PKIMessage  – the outermost wrapper
# ---------------------------------------------------------------------------

class PKIMessage(Sequence):
    """
    The top-level CMP message structure (RFC 4210 Section 5.1).
    """
    _fields = [
        ('header', PKIHeader),
        ('body', PKIBody),
        ('protection', OctetBitString, {'explicit': 0, 'optional': True}),
        ('extra_certs', CMPCertificates, {'explicit': 1, 'optional': True}),
    ]

    @property
    def message_type(self):
        return self['body'].name

    @property
    def transaction_id(self):
        return self['header']['transaction_id']

    @property
    def sender_nonce(self):
        return self['header']['sender_nonce']

    @property
    def recip_nonce(self):
        return self['header']['recip_nonce']

    @property
    def sender(self):
        return self['header']['sender']

    @property
    def recipient(self):
        return self['header']['recipient']

    @property
    def protection_alg(self):
        return self['header']['protection_alg']

    @property
    def is_protected(self):
        return self['protection'].contents is not None

    @property
    def body_value(self):
        return self['body'].chosen


class PKIMessages(SequenceOf):
    """A sequence of PKIMessage objects, used for batched transport."""
    _child_spec = PKIMessage
