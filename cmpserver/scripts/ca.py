# coding: utf-8
import logging
import os

from asn1crypto import x509
from oscrypto import asymmetric
from certbuilder import CertificateBuilder

logger = logging.getLogger(__name__)

KEY_PASSWORD = None


def save_pub(public_key, path):
    """Saves a public key in DER form."""
    with open(path, 'wb') as f:
        f.write(asymmetric.dump_public_key(public_key))
    logger.debug('wrote %s', path)


def save_key(private_key, path):
    """Saves a private key in DER form."""
    with open(path, 'wb') as f:
        f.write(asymmetric.dump_private_key(private_key, KEY_PASSWORD, target_ms=20))
    logger.debug('wrote %s', path)


def save_cert(certificate, path):
    """DER-encodes and saves a certificate."""
    with open(path, 'wb') as f:
        f.write(asymmetric.dump_certificate(certificate))
    logger.debug('wrote %s', path)


DN_KEY_MAP = {
    'CN': 'common_name',
    'C': 'country_name',
    'L': 'locality_name',
    'ST': 'state_or_province_name',
    'O': 'organization_name',
    'OU': 'organizational_unit_name',
    'E': 'email_address',
    'DC': 'domain_component',
}


def normalize_name_input(data):
    """Adapts a DN string / dict / Name into a standard dict form."""
    if isinstance(data, dict):
        return data

    if isinstance(data, str):
        result_dict = {}
        for part in data.split(','):
            if '=' not in part:
                continue
            key, val = part.split('=', 1)
            key = key.strip().upper()
            val = val.strip()
            standard_key = DN_KEY_MAP.get(key)
            if standard_key:
                result_dict[standard_key] = val
        return result_dict

    raise TypeError('Unsupported input type: %s' % type(data))


DEFAULT_ROOT_CERT_INFO = {
    "ca_subject": "DC=example,C=US,ST=Example,L=Example,O=Example Org,OU=Engineering,CN=Test Root CA,E=ca@example.org",
    "ca_key_size": 2048,
    "ca_validity": 3650,
    "ca_pub_file": "ca_pub.pem",
    "ca_key_file": "ca_key.pem",
    "ca_cert_file": "ca_cert.pem",
}


def _default_output_dir():
    """Default output directory for generated certificates (tests/output)."""
    return os.path.join(os.getcwd(), 'tests', 'output')


def create_root_cert(ca_info=None, onlyData=False, output_dir=None):
    """Create a self-signed root CA.

    :param ca_info: dict with ca_subject / ca_key_size / ca_validity and file names.
    :param onlyData: if True, return (private_key, certificate) without writing files.
    :param output_dir: directory to write the PEM files into (default: tests/output).
    :return: (private_key, certificate)
    """
    if ca_info is None:
        ca_info = DEFAULT_ROOT_CERT_INFO
    logger.debug('Generating root CA key pair ...')
    root_ca_pub, root_ca_priv = asymmetric.generate_pair(
        'rsa', bit_size=ca_info['ca_key_size']
    )
    ca_subject = normalize_name_input(ca_info['ca_subject'])

    builder = CertificateBuilder(ca_subject, root_ca_pub)
    if ca_info.get('begin_date'):
        builder.begin_date = ca_info['begin_date']
    if ca_info.get('end_date'):
        builder.end_date = ca_info['end_date']
    builder.self_signed = True
    builder.ca = True

    builder.set_extension('authority_key_identifier', x509.AuthorityKeyIdentifier({
        'key_identifier': root_ca_pub.asn1.sha1
    }))
    root_ca_cert = builder.build(root_ca_priv)

    if onlyData:
        return root_ca_priv, root_ca_cert

    out = output_dir or _default_output_dir()
    os.makedirs(out, exist_ok=True)
    save_pub(root_ca_pub, os.path.join(out, ca_info['ca_pub_file']))
    save_key(root_ca_priv, os.path.join(out, ca_info['ca_key_file']))
    save_cert(root_ca_cert, os.path.join(out, ca_info['ca_cert_file']))
    return root_ca_priv, root_ca_cert


def issue_end_entity(issuer_cert, issuer_priv, subject, subject_pub, subject_ext):
    """Issue an end-entity certificate signed by the CA."""
    builder = CertificateBuilder(subject, subject_pub)
    builder.issuer = issuer_cert
    builder.ca = False
    for ext in subject_ext:
        builder.set_extension(ext['extn_id'], ext['extn_value'].parsed)
    return builder.build(issuer_priv)
