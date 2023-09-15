"""
Functions used for certificate revocation operations
"""
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto

from webca.crypto.extensions import get_certificate_extension
from webca.crypto.utils import datetime_to_asn1, int_to_hex

REASON_UNSPECIFIED = crypto.Revoked().all_reasons()[0]


# is_delta=False, delta_number=None, crl_locations=None
def create_crl(revoked_list, days, issuer, number):
    """Create a CRL using cryptography's API and then convert it to pyopenssl.

    Arguments
    ----------
    `revoked_list` - list of integers that represent the serial number of the revoked certificates
    `days` - number of days for the next update
    `issuer` - cert,key tuple of the certificate used to sign the CRL
    `number` - CRL sequence number
    """
    issuer_cert, issuer_key = issuer
    # crl_locations = crl_locations or []

    builder = x509.CertificateRevocationListBuilder()
    name_attrs = []
    if issuer_cert.get_subject().CN:
        name_attrs.append(
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME,
                issuer_cert.get_subject().CN
            )
        )
    if issuer_cert.get_subject().C:
        name_attrs.append(
            x509.NameAttribute(
                x509.oid.NameOID.COUNTRY_NAME,
                issuer_cert.get_subject().C
            )
        )
    if issuer_cert.get_subject().ST:
        name_attrs.append(
            x509.NameAttribute(
                x509.oid.NameOID.STATE_OR_PROVINCE_NAME,
                issuer_cert.get_subject().ST
            )
        )
    if issuer_cert.get_subject().L:
        name_attrs.append(
            x509.NameAttribute(
                x509.oid.NameOID.LOCALITY_NAME,
                issuer_cert.get_subject().L
            )
        )
    if issuer_cert.get_subject().O:
        name_attrs.append(
            x509.NameAttribute(
                x509.oid.NameOID.ORGANIZATION_NAME,
                issuer_cert.get_subject().O
            )
        )
    if issuer_cert.get_subject().OU:
        name_attrs.append(
            x509.NameAttribute(
                x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME,
                issuer_cert.get_subject().OU
            )
        )
    builder = builder.issuer_name(x509.Name(name_attrs))
    builder = builder.last_update(datetime.utcnow())
    builder = builder.next_update(datetime.utcnow() + timedelta(days=days))

    for serial, date, reason in revoked_list:
        ext = x509.CRLReason(x509.ReasonFlags(reason))
        revoked_cert = x509.RevokedCertificateBuilder(
        ).serial_number(
            serial
        ).revocation_date(
            date
        ).add_extension(
            ext, False
        ).build(default_backend())
        builder = builder.add_revoked_certificate(revoked_cert)

    # To add the AKI extension, we have to read the SKI extension from the
    # signing certificate
    ski = get_certificate_extension(issuer_cert, b'subjectKeyIdentifier')
    if ski:
        ski = bytes.fromhex(str(ski).replace(':', '').lower())
        ext = x509.AuthorityKeyIdentifier(ski, None, None)
        builder = builder.add_extension(ext, False)

    # Add CRL Number
    ext = x509.CRLNumber(number)
    builder = builder.add_extension(ext, False)

    # Add Delta CRL Number
    # if is_delta:
    #     if number >= delta_number:
    #         raise ValueError('delta_number')
    #     ext = x509.DeltaCRLIndicator(delta_number)
    #     builder = builder.add_extension(ext, False)

    # FUTURE: Add Freshest CRL. Cryptography doesn't support building
    # CRLs with this extension so we can't create Delta CRLs right now
    # if not is_delta and crl_locations:
    #     url = crl_locations[0]
    #     point = x509.DistributionPoint(
    #         full_name=[x509.DNSName(url)],
    #         relative_name=None,
    #         reasons=None,
    #         crl_issuer=None,
    #     )
    #     ext = x509.FreshestCRL(distribution_points=[point])
    #     builder = builder.add_extension(ext, False)

    # FUTURE: add Issuing Distribution Point
    # This extension is not supported by criptography either
    # https://tools.ietf.org/html/rfc5280#section-5.2.5
    #    Although the extension is critical, conforming implementations
    #    are not required to support this extension.
    #    However, implementations that do not support this extension
    #    MUST either treat the status of any certificate not listed
    #    on this CRL as unknown or locate another CRL that does not
    #    contain any unrecognized critical extensions.

    crl = builder.sign(
        issuer_key.to_cryptography_key(),
        hashes.SHA256(),
        default_backend(),
    )

    openssl_crl = crypto.CRL.from_cryptography(crl)
    return openssl_crl
