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
        with the certificate serial number"""
        cert = self._get_certificate(serial)
        if cert:
            return cert.keys.get_private_key()

    def get_public_key(self, serial):
        """Return the public OpenSSL.crypto.PKey associated
        with the certificate serial number"""
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

    def get_certificates(self, keyUsage=[], extendedKeyUsage=[]):
        """Return a list of OpenSSL.crypto.X509 that match the list of keyUsage
        and/or extendedKeyUsage.

        keyUsage is a list of webca.crypto.constants.KEY_USAGE
        extendedKeyUsage is a list of webca.crypto.constants.EXT_KEY_USAGE
        """
        certs = {}

        for ku in keyUsage:
            matches = Certificate.objects.filter(key_usage__icontains=ku)
            for c in matches:
                certs[c.serial] = c
        for eku in extendedKeyUsage:
            matches = Certificate.objects.filter(ext_key_usage__icontains=eku)
            for c in matches:
                certs[c.serial] = c

        certs = certs.values()
        if len(certs) == 0 and len(keyUsage) == 0 and len(extendedKeyUsage) == 0:
            certs = Certificate.objects.all()

        return [x.get_certificate() for x in certs]

    def add_certificate(self, private_key, certificate):
        """Add an OpenSSL.crypto.X509 certificate and
        its OpenSSL.crypto.PKey private key."""
        with transaction.atomic(using=DATABASE_LABEL):
            keys = KeyPair.from_keypair(private_key)
            if keys is None:
                raise ValueError('private_key')
            cert = Certificate.from_certificate(certificate)
            keys.name = "%s - %s" % (str(cert), cert.serial)
            keys.save()
            cert.keys = keys
            cert.save()
        return certificate
