# coding: utf-8
import logging

from cmp_mock_tester.asn1crypto_cmp.rfc4210 import PKIMessage
from cmp_mock_tester.cmpbuilder import CMPResponseBuilder, CMPConfirmBuilder
from cmp_mock_tester.scripts.ca import issue_end_entity

logger = logging.getLogger(__name__)


def msgHandler(cmp_config, req):
    pki_msg = PKIMessage.load(req)
    body = pki_msg['body']
    body_name = body.name
    body_value = body.chosen
    if body_name == 'ir':
        return InitializationResponse(pki_msg, body_value, cmp_config)
    elif body_name == 'kur':
        return KeyUpdateResponseContent(pki_msg, body_value, cmp_config)
    elif body_name == 'certconf':
        return PKIComfirmationContent(pki_msg, cmp_config)
    raise ValueError('Unsupported CMP body type: %r' % body_name)


def InitializationResponse(pki_msg, ir_msg, cmp_config):
    ca_info = cmp_config.ca_info
    header = pki_msg['header']
    # 默认：sender/recipient 取自请求头并对调。
    # 想覆盖 sender，用 cmp_config.mock.header['sender'] = general_name(...)（签名前注入）。
    sender = header['recipient']
    recipient = header['sender']
    builder = CMPResponseBuilder('ip', sender, recipient)
    builder.set_from_request(pki_msg)
    for crm in ir_msg:
        cert_req = crm['cert_req']
        template = cert_req['cert_template']
        # ---提取公钥---
        pub_key = template['public_key']
        subject_der = template['subject']
        extensions = template['extensions']
        ee_crt = issue_end_entity(ca_info['issuer_cert'], ca_info['issuer_key'], subject_der, pub_key, extensions)
        builder.add_accepted(cert_req['cert_req_id'].native, ee_crt)
    ip_response = builder.build(ca_info['issuer_key'], ca_info['issuer_cert'], cmp_config)
    der_bytes = ip_response.dump()
    return der_bytes


def KeyUpdateResponseContent(pki_msg, kur_msg, cmp_config):
    ca_info = cmp_config.ca_info
    header = pki_msg['header']
    sender = header['recipient']
    recipient = header['sender']
    builder = CMPResponseBuilder('kup', sender, recipient)
    builder.set_from_request(pki_msg)
    for crm in kur_msg:
        cert_req = crm['cert_req']
        template = cert_req['cert_template']
        # ---提取公钥---
        pub_key = template['public_key']
        subject_der = template['subject']
        extensions = template['extensions']
        ee_crt = issue_end_entity(ca_info['issuer_cert'], ca_info['issuer_key'], subject_der, pub_key, extensions)
        builder.add_accepted(cert_req['cert_req_id'].native, ee_crt)
    ip_response = builder.build(ca_info['issuer_key'], ca_info['issuer_cert'], cmp_config)
    der_bytes = ip_response.dump()
    return der_bytes


def PKIComfirmationContent(pki_msg, cmp_config):
    ca_info = cmp_config.ca_info
    header = pki_msg['header']
    sender = header['recipient']
    recipient = header['sender']
    builder = CMPConfirmBuilder('pkiconf', sender, recipient)
    builder.set_from_response(pki_msg)
    pkiconf_response = builder.build(cmp_config, ca_info['issuer_key'], ca_info['issuer_cert'])
    der_bytes = pkiconf_response.dump()
    return der_bytes
