"""
Test the extensions functions.
"""
from cryptography import x509
from django.test import TestCase
from OpenSSL import crypto

from . import certs, extensions


class KeyUsage(TestCase):
    """Test the extensions functions."""

    def test_empty(self):
        """KeyUsage"""
        ext = extensions.KeyUsage()
        self.assertEqual(ext.value(), '')

    def test_one(self):
        """KeyUsage"""
        ext = extensions.KeyUsage().digitalSignature()
        self.assertEqual(ext.value(), 'digitalSignature')
        self.assertEqual(ext.values(), ['digitalSignature'])

    def test_two(self):
        """KeyUsage"""
        ext = extensions.KeyUsage().digitalSignature().nonRepudiation()
        self.assertEqual(ext.value(), 'digitalSignature,nonRepudiation')
        self.assertEqual(ext.values(), ['digitalSignature', 'nonRepudiation'])

    def test_list(self):
        """KeyUsage"""
        ext = extensions.KeyUsage().from_list('digitalSignature')
        self.assertEqual(ext.value(), 'digitalSignature')
        self.assertEqual(ext.values(), ['digitalSignature'])

    def test_list_two(self):
        """KeyUsage"""
        ext = extensions.KeyUsage().from_list('digitalSignature,nonRepudiation')
        self.assertEqual(ext.value(), 'digitalSignature,nonRepudiation')
        self.assertEqual(ext.values(), ['digitalSignature', 'nonRepudiation'])

    def test_from_x509(self):
        """KeyUsage.from_extension"""
        x509ext = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=True,
            encipher_only=True,
            decipher_only=True,
            key_cert_sign=True,
            crl_sign=True,
        )
        ext = extensions.KeyUsage.from_extension(x509ext)
        self.assertTrue('digitalSignature' in ext.value())
        self.assertEqual(len(ext.values()), 9)

    def test_from_x509_invalid(self):
        """KeyUsage.from_extension"""
        x509ext = x509.CRLNumber(1)
        self.assertRaises(ValueError, extensions.KeyUsage.from_extension, x509ext)

class ExtendedKeyUsage(TestCase):
    """Extended key usage"""

    def test_from_x509(self):
        """ExtendedKeyUsage.from_extension"""
        x509ext = x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING,
        ])
        ext = extensions.ExtendedKeyUsage.from_extension(x509ext)
        self.assertTrue('OCSPSigning' in ext.value())

    def test_from_x509_invalid(self):
        """ExtendedKeyUsage.from_extension"""
        x509ext = x509.CRLNumber(1)
        self.assertRaises(ValueError, extensions.ExtendedKeyUsage.from_extension, x509ext)

class Utils(TestCase):
    """General utils"""

    def test_get_certificate_extension(self):
        """get_certificate_extension"""
        _, cert = certs.create_ca_certificate([('CN', 'test')])
        ext = extensions.get_certificate_extension(cert, b'basicConstraints')
        self.assertIsNotNone(ext)

    def test_get_certificate_extension_empty(self):
        """get_certificate_extension"""
        _, cert = certs.create_ca_certificate([('CN', 'test')])
        ext = extensions.get_certificate_extension(cert, b'extendedKeyUsage')
        self.assertIsNone(ext)

    def test_get_extension(self):
        """get_certificate_extension"""
        _, cert = certs.create_ca_certificate([('CN', 'test')])
        ext = extensions.get_extension(cert, 'basicConstraints')
        self.assertIsNotNone(ext)

    def test_get_extension_empty(self):
        """get_certificate_extension"""
        _, cert = certs.create_ca_certificate([('CN', 'test')])
        ext = extensions.get_extension(cert, b'extendedKeyUsage')
        self.assertIsNone(ext)

    def test_json(self):
        """json_to_extension"""
        json = '{"name":"basicConstraints", "critical":true,"value":"CA:TRUE"}'
        self.assertIsInstance(extensions.json_to_extension(json), crypto.X509Extension)

    def test_san(self):
        """build_san"""
        names = 'DNS:test'
        san = extensions.build_san(names, False)
        self.assertIsInstance(san, crypto.X509Extension)
        self.assertEqual(san.get_short_name(), b'subjectAltName')

    def test_san_critical(self):
        """build_san"""
        names = 'DNS:test'
        san = extensions.build_san(names, False)
        self.assertFalse(san.get_critical())
        san = extensions.build_san(names, True)
        self.assertTrue(san.get_critical())

    def test_cdp(self):
        """build_cdp"""
        names = 'URI:test'
        cdp = extensions.build_cdp(names, False)
        self.assertIsInstance(cdp, crypto.X509Extension)
        self.assertEqual(cdp.get_short_name(), b'crlDistributionPoints')

    def test_cdp_critical(self):
        """build_cdp"""
        names = 'URI:test'
        cdp = extensions.build_cdp(names, False)
        self.assertFalse(cdp.get_critical())
        cdp = extensions.build_cdp(names, True)
        self.assertTrue(cdp.get_critical())
