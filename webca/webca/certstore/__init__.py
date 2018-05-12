"""
This module defines the abstract class CertStore from which different stores
have to inherit so that can provide the same features.
"""
import abc

from webca.crypto.constants import KU_KEYCERTSIGN, KU_CRLSIGN


class CertStore(metaclass=abc.ABCMeta):
    """"This class is to be used to track the different
    implementations of a certificate store."""
    CLASS_ID = 'cfb28a77-eed7-4c91-9061-2ba0d3d2bea9'

    _stores = {}

    @staticmethod
    def register_store(store_class):
        """Register a store implementation."""
        if issubclass(store_class, CertStore):
            CertStore._stores[store_class.STORE_ID] = (
                store_class.__name__,
                store_class,
            )

    @staticmethod
    def all():
        """Return a list of tuples with `(name, cls)` of all available stores."""
        return [(name, cls) for name, cls in CertStore._stores.values()]

    @staticmethod
    def stores():
        """Return a list of objects with all available stores."""
        return [cls() for name, cls in CertStore.all()]

    @staticmethod
    def get_store(store_id):
        """Return an instance of the selected store."""
        store = CertStore._stores[store_id]
        return store[1]()

    @abc.abstractmethod
    def add_certificate(self, private_key, certificate):
        """Add an OpenSSL.crypto.X509 `certificate` and
        its OpenSSL.crypto.PKey `private_key`."""
        return

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
    def get_certificates(self, key_usage=None, ext_key_usage=None):
        """Return a list of OpenSSL.crypto.X509 that match the list of keyUsage
        and/or extendedKeyUsage.

        key_usage is a list of webca.crypto.constants.KU_*
        ext_key_usage is a list of webca.crypto.constants.EKU_*
        """
        return

    def get_ca_certificates(self):
        """Return the certificates that can sign other certificates."""
        return self.get_certificates(key_usage=[KU_KEYCERTSIGN])

    def get_crl_certificates(self):
        """Return the  certificates that can sign CRLs."""
        return self.get_certificates(key_usage=[KU_CRLSIGN])
