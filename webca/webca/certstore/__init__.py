"""
This module defines the abstract class CertStore from which different stores
have to inherit so that can provide the same features.
"""
import abc


class CertStore(metaclass=abc.ABCMeta):
    """"This class is to be used to track the different
    implementations of a certificate store."""
    CLASS_ID = 'cfb28a77-eed7-4c91-9061-2ba0d3d2bea9'

    stores = []

    @staticmethod
    def register_store(cls):
        if issubclass(cls, CertStore):
            CertStore.stores.append((cls.__name__, cls.STORE_ID, cls))

    @abc.abstractmethod
    def get_private_key(self, serial):
        """Return the private OpenSSL.crypto.PKey associated
        with the certificate serial number"""
        return

    @abc.abstractmethod
    def get_public_key(self, serial):
        """Return the public OpenSSL.crypto.PKey associated
        with the certificate serial number"""
        return

    @abc.abstractmethod
    def get_certificate(self, serial):
        """Return a OpenSSL.crypto.X509 certificate with this serial number."""
        return

    @abc.abstractmethod
    def get_certificates(self, keyUsage, extendedKeyUsage):
        """Return a list of OpenSSL.crypto.X509 that match the list of keyUsage
        and/or extendedKeyUsage.

        keyUsage is a list of webca.crypto.constants.KEY_USAGE
        extendedKeyUsage is a list of webca.crypto.constants.EXT_KEY_USAGE
        """
        return

    @abc.abstractmethod
    def add_certificate(self, private_key, certificate):
        """Add an OpenSSL.crypto.X509 certificate and
        its OpenSSL.crypto.PKey private key."""
        return
