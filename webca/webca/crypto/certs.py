"""
Functions used for certificate operations
"""

from OpenSSL import crypto

from webca.crypto.constants import CERT_DURATION
from webca.crypto.utils import new_serial

# Creation functions


def create_key_pair(key_type, bits):
    """
    Create a public/private key pair.

    Arguments:
        key_type - crypto.TYPE_RSA or crypto.TYPE_DSA
        bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(key_type, bits)
    return pkey


def create_cert_request(pkey, name, extensions=None, digest='sha256', signing_key=None):
    """
    Create a certificate request.

    Arguments:
        pkey       - The key to associate with the request
        digest     - Digestion method to use for signing, default is sha256
        extensions - List of X509Extensions to add to the request
        name     - The name of the subject of the request, possible
                    arguments are:
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


def create_certificate(request, issuerCertKey, serial, validityPeriod, digest="sha256"):
    """
    Generate a certificate given a certificate request.

    Arguments:
        request - Certificate request to use
        issuerCert - The certificate of the issuer
        issuerKey  - The private key of the issuer
        serial     - Serial number for the certificate
        notBefore  - Timestamp (relative to now) when the certificate
                    starts being valid
        notAfter   - Timestamp (relative to now) when the certificate
                    stops being valid
        digest     - Digest method to use for signing, default is sha256
    Returns: The signed certificate in an X509 object
    """
    # TODO: Check signing cert validity period against the new cert validity period
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod

    cert = crypto.X509()
    cert.set_version(2)  # 2 for v3
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(request.get_subject())
    cert.set_pubkey(request.get_pubkey())

    cert.add_extensions(request.get_extensions())
    ski = crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', cert)
    cert.add_extensions([ski])
    if isinstance(issuerCert, crypto.X509):
        # issuerCert could be a X509Req if this is a self-signed cert
        aki = crypto.X509Extension(
            b'authorityKeyIdentifier', False, b'keyid,issuer', issuer=issuerCert)
    else:
        aki = crypto.X509Extension(
            b'authorityKeyIdentifier', False, b'keyid,issuer', issuer=cert)
    cert.add_extensions([aki])

    cert.sign(issuerKey, digest)
    return cert


def create_ca_certificate(name, bits=2048, pathlen=-1, duration=CERT_DURATION, signing_cert=None):
    """
    Create a self-signed certificate to be used in a CA.

    Arguments: name     - Distinguished name as a dict of components
               bits     - Size of the key to generate
               duration - Time in seconds (default: 5 years)
    Returns:   The signed certificate in a X509 object
    """
    basic_constraints = b'CA:TRUE'
    if pathlen > -1:
        basic_constraints += (', pathlen:%d' % pathlen).encode('ascii')
    ca_extensions = [
        crypto.X509Extension(b'basicConstraints', True, basic_constraints),
        crypto.X509Extension(b'keyUsage', True, b'keyCertSign,cRLSign')
    ]
    serial = new_serial()
    ca_key = create_key_pair(crypto.TYPE_RSA, bits)
    ca_req = create_cert_request(ca_key, name, ca_extensions)
    if not signing_cert:
        signing_cert = (ca_req, ca_key)
    ca_cert = create_certificate(ca_req, signing_cert, serial, (0, duration))
    return ca_key, ca_cert
