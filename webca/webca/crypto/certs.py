"""
Functions used for certificate operations
"""
from datetime import datetime, timedelta

import pytz
from OpenSSL import crypto

from webca.crypto import constants as c
from webca.crypto.exceptions import CryptoException
from webca.crypto.utils import asn1_to_datetime, new_serial

# Creation functions


def create_key_pair(key_type, bits):
    """
    Create a public/private key pair.

    Arguments:
        key_type - crypto.TYPE_RSA or crypto.TYPE_DSA
        bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    if key_type == c.KEY_RSA:
        key_type = crypto.TYPE_RSA
    elif key_type == c.KEY_DSA:
        key_type = crypto.TYPE_DSA
    else:
        raise ValueError('key_type cannot be KEY_EC')
    pkey = crypto.PKey()
    pkey.generate_key(key_type, bits)
    return pkey


def create_cert_request(pkey, name, extensions=None, digest='sha256', signing_key=None):
    """
    Create a certificate request.

    Arguments:
        pkey: The key to associate with the request
        extensions: List of X509Extensions to add to the request
        name: The name of the subject of the request, possible arguments are:
                C     - Country name
                ST    - State or province name
                L     - Locality name
                O     - Organization name
                OU    - Organizational unit name
                CN    - Common name
                emailAddress - E-mail address
                For example:
                    name = [
                        ('CN', 'Certificate Authority')
                    ]
        digest: Digestion method to use for signing, default is sha256
        signing_key: Key used to sign the request
    Returns:   The certificate request in an X509Req object
    """
    extensions = extensions or []
    request = crypto.X509Req()
    subj = request.get_subject()

    for key, value in name:
        setattr(subj, key, value)
    request.set_pubkey(pkey)
    request.add_extensions(extensions)
    if signing_key:
        request.sign(signing_key, digest)
    else:
        request.sign(pkey, digest)
    return request


def create_certificate(request, issuer_cert_key, serial, validity_period, digest="sha256"):
    """
    Generate a certificate given a certificate request.

    Arguments
    ---------
    `request` - X509Req request to use
    `issuer_cert` - X509 certificate of the issuer
    `issuer_key` - private PKey of the issuer
    `serial` - Serial number for the certificate
    `not_before` - Timestamp (relative to now) when the certificate starts being valid
    `notAfter` - Timestamp (relative to now) when the certificate stops being valid
    `digest` - Digest method to use for signing, default is sha256
    Returns: The signed certificate in an X509 object
    """
    # Check signing cert validity period against the new cert validity period
    issuer_cert, issuer_key = issuer_cert_key
    not_before, not_after = validity_period
    new_valid_from = datetime.now(pytz.utc) + timedelta(seconds=not_before)
    new_valid_to = datetime.now(pytz.utc) + timedelta(seconds=not_after)
    # Validity period check only makes sense if issuer_cert is a X509
    if isinstance(issuer_cert, crypto.X509):
        signing_valid_from = asn1_to_datetime(
            issuer_cert.get_notBefore().decode('utf-8'))
        signing_valid_to = asn1_to_datetime(
            issuer_cert.get_notAfter().decode('utf-8'))
        if signing_valid_from > new_valid_from:
            raise CryptoException(
                "The new certificate validity spans beyond the CA certificate's")
        if signing_valid_to < new_valid_to:
            raise CryptoException(
                "The new certificate validity spans beyond the CA certificate's")

    cert = crypto.X509()
    cert.set_version(2)  # 2 for v3
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(not_before)
    cert.gmtime_adj_notAfter(not_after)
    cert.set_issuer(issuer_cert.get_subject())
    cert.set_subject(request.get_subject())
    cert.set_pubkey(request.get_pubkey())

    cert.add_extensions(request.get_extensions())
    ski = crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', cert)
    cert.add_extensions([ski])
    if isinstance(issuer_cert, crypto.X509):
        # issuer_cert could be a X509Req if this is a self-signed cert
        aki = crypto.X509Extension(
            b'authorityKeyIdentifier', False, b'keyid:always,issuer:always', issuer=issuer_cert)
    else:
        aki = crypto.X509Extension(
            b'authorityKeyIdentifier', False, b'keyid:always,issuer:always', issuer=cert)
    cert.add_extensions([aki])

    cert.sign(issuer_key, digest)
    return cert


def create_self_signed(name, key_type=c.KEY_RSA, bits=2048, duration=c.CERT_DURATION, extensions=None):
    """
    Create a self-signed certificate.
    """
    extensions = extensions or [
        crypto.X509Extension(b'keyUsage', True, b'digitalSignature')
    ]
    serial = new_serial()
    key = create_key_pair(key_type, bits)
    req = create_cert_request(key, name, extensions)
    signing_cert = (req, key)
    cert = create_certificate(req, signing_cert, serial, (0, duration))
    return key, cert


def create_ca_certificate(name, bits=2048, pathlen=-1, duration=c.CERT_DURATION, signing_cert=None):
    """
    Create a self-signed certificate to be used in a CA.

    Arguments
    ---------
    `name` - Distinguished name as a dict of components
    `bits` - Size of the key to generate
    `pathlen` - Pathlen value in BasicConstraints
    `duration` - Time in seconds (default: `constants.CERT_DURATION`)
    Returns: The signed certificate in a `OpenSSL.crytpo.X509`
    """
    basic_constraints = b'CA:TRUE'
    if pathlen > -1:
        basic_constraints += (', pathlen:%d' % pathlen).encode('ascii')
    ca_extensions = [
        crypto.X509Extension(b'basicConstraints', True, basic_constraints),
        crypto.X509Extension(b'keyUsage', True, b'keyCertSign,cRLSign'),
    ]
    serial = new_serial()
    ca_key = create_key_pair(c.KEY_RSA, bits)
    ca_req = create_cert_request(ca_key, name, ca_extensions)
    if not signing_cert:
        signing_cert = (ca_req, ca_key)
    ca_cert = create_certificate(ca_req, signing_cert, serial, (0, duration))
    return ca_key, ca_cert
