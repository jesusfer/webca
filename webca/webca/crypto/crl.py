"""
Functions used for certificate revocation operations
"""
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto

from webca.crypto.extensions import *
from webca.crypto.utils import *

REASON_UNSPECIFIED = crypto.Revoked().all_reasons()[0]


def revoke_certificate(certificate,
                       reason=REASON_UNSPECIFIED, rev_date=datetime.utcnow()):
    """Revoke a X509 certificate."""
    rev = crypto.Revoked()
    rev.set_serial(serial_int_to_bytes(certificate.get_serial_number()))
    rev.set_reason(reason)
    rev.set_rev_date(datetime_to_asn1(rev_date))
    return rev


def create_crl(revoked_list, next_update_days, issuer):
    """Create a CRL using just pyopenssl.

    Cannot use extensions with this function.
    """
    issuer_cert, issuer_key = issuer
    crl = crypto.CRL()
    for revoked in revoked_list:
        crl.add_revoked(revoked)
    this_update = datetime.utcnow()
    next_update = this_update + timedelta(days=next_update_days)
    crl.set_lastUpdate(datetime_to_asn1(this_update))
    crl.set_nextUpdate(datetime_to_asn1(next_update))
    crl.set_version(1)  # for v2

    _crl = crl.to_cryptography()
    return crl


def create_crl2(serial_list, days, issuer):
    """Create a CRL using cryptography's API and then convert it to pyopenssl.
    
    There is a mix of APIs here.
    Parameters
    ----------
    serial_list - list of integers that represent the serial number of the revoked certificates
    days - number of days for the next update
    issuer - cert,key of the certificate used to sign the CRL
    """
    issuer_cert, issuer_key = issuer

    builder = x509.CertificateRevocationListBuilder()
    # FIXME: use the rest of the name attributes here
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, issuer_cert.get_subject().CN)
    ]))
    builder = builder.last_update(datetime.utcnow())
    builder = builder.next_update(datetime.utcnow() + timedelta(days=days))

    for serial in serial_list:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            serial
        ).revocation_date(
            datetime.utcnow()
        ).build(default_backend())
        builder = builder.add_revoked_certificate(revoked_cert)

    # To add the AKI extension, we have to read the SKI extension from the
    # signing certificate
    ski = get_certificate_extension(issuer_cert, b'subjectKeyIdentifier')
    if ski:
        ski = bytes.fromhex(str(ski).replace(':','').lower())
        ext = x509.AuthorityKeyIdentifier(ski, None, None)
        builder = builder.add_extension(ext, False)

    crl = builder.sign(issuer_key.to_cryptography_key(),
                       hashes.SHA256(), default_backend())
    
    openssl_crl = crypto.CRL.from_cryptography(crl)
    return openssl_crl
