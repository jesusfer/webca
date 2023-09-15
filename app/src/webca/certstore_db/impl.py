"""
A CertStore implementation that uses Djando models to store the CA certificates.
"""
from django.db import transaction

from webca.certstore import CertStore
from webca.certstore_db import DATABASE_LABEL
from webca.certstore_db.models import Certificate, KeyPair
from webca.crypto.constants import EXT_KEY_USAGE, KEY_USAGE


class DatabaseStore(CertStore):
    """Certificate store with Django models as backend."""
    STORE_ID = '9a16e500-cc97-48e4-9b62-4e41d91c2607'

    def get_private_key(self, serial):
        """Return the private OpenSSL.crypto.PKey associated
        with the certificate serial number."""
        cert = self._get_certificate(serial)
        if cert:
            return cert.keys.get_private_key()
        return None

    def get_public_key(self, serial):
        """Return the public OpenSSL.crypto.PKey associated
        with the certificate serial number."""
        cert = self._get_certificate(serial)
        if cert:
            return cert.keys.get_public_key()
        return cert.get_certificate().get_pubkey()

    def _get_certificate(self, serial):
        """Return a OpenSSL.crypto.X509 certificate with this serial number."""
        if isinstance(serial, int):
            serial = '%x' % serial
        certs = Certificate.objects.filter(serial__exact=serial)
        if len(certs) == 1:
            return certs[0]
        return None

    def get_certificate(self, serial):
        """Return a OpenSSL.crypto.X509 certificate with this serial number."""
        cert = self._get_certificate(serial)
        if cert:
            return cert.get_certificate()
        return None

    def get_certificates(self, key_usage=None, ext_key_usage=None):
        """Return a list of OpenSSL.crypto.X509 that match the list of key_usage
        and/or ext_key_usage.

        key_usage is a list of webca.crypto.constants.KU_*
        ext_key_usage is a list of webca.crypto.constants.EKU_*
        """
        certs = {}
        key_usage = key_usage or []
        ext_key_usage = ext_key_usage or []

        for usage in key_usage:
            value = KEY_USAGE[usage]
            matches = Certificate.objects.filter(key_usage__icontains=value)
            for cert in matches:
                certs[cert.serial] = cert
        for usage in ext_key_usage:
            value = EXT_KEY_USAGE[usage]
            matches = Certificate.objects.filter(
                ext_key_usage__icontains=value)
            for cert in matches:
                certs[cert.serial] = cert

        certs = certs.values()
        if not certs and not key_usage and not ext_key_usage:
            certs = Certificate.objects.all()

        return [x.get_certificate() for x in certs]

    def add_certificate(self, private_key, certificate):
        """Add an OpenSSL.crypto.X509 certificate and
        its OpenSSL.crypto.PKey private key."""
        with transaction.atomic(using=DATABASE_LABEL):
            keys = KeyPair.from_keypair(private_key)
            if not keys:
                raise ValueError('private_key')
            cert = Certificate.from_certificate(certificate)
            keys.name = "%s - %s" % (str(cert), cert.serial)
            keys.save()
            cert.keys = keys
            cert.save()
        return certificate
