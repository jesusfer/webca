"""
Tests for the crypto module.
"""
from datetime import datetime, timedelta

import pytz
from cryptography import x509
from django.test import TestCase
from OpenSSL import crypto

from . import constants as c
from . import certs, crl, utils
from .exceptions import CryptoException


class KeyPair(TestCase):
    """create_key_pair"""

    def test_key_pair(self):
        """Test that we get what we asked for."""
        key_pair = certs.create_key_pair(c.KEY_RSA, 512)
        self.assertIsInstance(key_pair, crypto.PKey)
        self.assertEqual(key_pair.bits(), 512)
        self.assertEqual(key_pair.type(), crypto.TYPE_RSA)
        key_pair = certs.create_key_pair(c.KEY_DSA, 512)
        self.assertIsInstance(key_pair, crypto.PKey)
        self.assertEqual(key_pair.bits(), 512)
        self.assertEqual(key_pair.type(), crypto.TYPE_DSA)

    def test_key_type(self):
        """Test correct args."""
        self.assertRaises(ValueError,
                          certs.create_key_pair, key_type=c.KEY_EC, bits=512)
        self.assertRaises(ValueError,
                          certs.create_key_pair, key_type=-1, bits=512)
        self.assertRaises(ValueError,
                          certs.create_key_pair, key_type=4, bits=512)
        self.assertRaises(ValueError,
                          certs.create_key_pair, key_type='1', bits=512)

    def test_bits(self):
        """Test correct args."""
        self.assertRaises(ValueError,
                          certs.create_key_pair, key_type=c.KEY_RSA, bits=-1)

class Request(TestCase):
    """create_cert_request"""

    def test_request(self):
        """Test correct type."""
        keys = certs.create_key_pair(c.KEY_RSA, 512)
        name = [
            ('CN', 'test'),
            ('C', 'ES'),
            ('ST', 'test'),
            ('L', 'test'),
            ('O', 'test'),
            ('OU', 'test'),
            ('emailAddress', 'test@test.net'),
        ]
        request = certs.create_cert_request(keys, name)
        self.assertIsInstance(request, crypto.X509Req)
    
    def test_signing(self):
        """Test signing key."""
        skey = certs.create_key_pair(c.KEY_RSA, 512)
        name = [('CN', 'test'),]
        keys = certs.create_key_pair(c.KEY_RSA, 512)
        request = certs.create_cert_request(keys, name, signing_key=skey)
        self.assertTrue(request.verify(skey))

    def test_extensions(self):
        """Test extensions."""
        name = [('CN', 'test'),]
        keys = certs.create_key_pair(c.KEY_RSA, 512)
        request = certs.create_cert_request(keys, name)
        self.assertEqual(request.get_extensions(), [])
        exts = [
            crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE')
        ]
        request = certs.create_cert_request(keys, name, exts)
        self.assertEqual(len(request.get_extensions()), 1)

class Certificate(TestCase):
    """create_certificate"""

    def build_certificate(self, name=None, add_exts=False):
        name = name or [
            ('CN', 'test'),
            ('C', 'ES'),
            ('ST', 'test'),
            ('L', 'test'),
            ('O', 'test'),
            ('OU', 'test'),
            ('emailAddress', 'test@test.net'),
        ]
        keys = certs.create_key_pair(c.KEY_RSA, 512)
        if add_exts:
            exts = [
                crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE')
            ]
        else:
            exts = []
        req = certs.create_cert_request(keys, name, exts)
        cert = certs.create_certificate(req, (req, keys), 1, (0, 3600))
        return keys, req, cert

    def build_certificate2(self, **kwargs):
        name = [
            ('CN', 'test2'),
            ('C', 'ES'),
            ('ST', 'test2'),
            ('L', 'test2'),
            ('O', 'test2'),
            ('OU', 'test2'),
            ('emailAddress', 'test2@test.net'),
        ]
        return self.build_certificate(name, **kwargs)

    def test_certificate(self):
        """Test correct type."""
        keys, req, cert = self.build_certificate()
        self.assertIsInstance(cert, crypto.X509)

    def test_serial(self):
        """Test serial."""
        keys, req, cert = self.build_certificate()
        self.assertEqual(cert.get_serial_number(), 1)

    def test_subject(self):
        """Test serial."""
        keys, req, cert = self.build_certificate()
        self.assertEqual(cert.get_subject().CN, 'test')
        self.assertEqual(cert.get_subject().C, 'ES')
        self.assertEqual(cert.get_subject().ST, 'test')
        self.assertEqual(cert.get_subject().L, 'test')
        self.assertEqual(cert.get_subject().O, 'test')
        self.assertEqual(cert.get_subject().OU, 'test')
        self.assertEqual(cert.get_subject().emailAddress, 'test@test.net')

    def test_pubkey(self):
        """Test pubkey."""
        keys, req, cert = self.build_certificate()
        pem1 = crypto.dump_publickey(crypto.FILETYPE_PEM, req.get_pubkey())
        pem2 = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())
        self.assertEqual(pem1, pem2)

    def test_issuer_name_self(self):
        """issuer name on self signed certs"""
        keys, req, cert = self.build_certificate()
        self.assertEqual(req.get_subject(), cert.get_subject())

    def test_issuer_name(self):
        """issuer name"""
        keys, req, cert = self.build_certificate()
        keys2, req2, cert2 = self.build_certificate2()
        certificate = certs.create_certificate(req, (cert2, keys2), 1, (0, 10))
        self.assertEqual(certificate.get_issuer(), req2.get_subject())

    def test_issuer_keyid(self):
        """issuer name"""
        keys, req, cert = self.build_certificate()
        keys2, req2, cert2 = self.build_certificate2()
        exts = dict()
        for i in range(0, cert2.get_extension_count()):
            exts[cert2.get_extension(i).get_short_name()] = cert2.get_extension(i)
        ca_ski = exts[b'subjectKeyIdentifier']
        certificate = certs.create_certificate(req, (cert2, keys2), 1, (0, 10))
        exts = dict()
        for i in range(0, certificate.get_extension_count()):
            exts[certificate.get_extension(i).get_short_name()] = certificate.get_extension(i)
        aki = exts[b'authorityKeyIdentifier']
        self.assertTrue(str(ca_ski) in str(aki))

    def test_issuer_signature(self):
        """issuer name"""
        keys, req, cert = self.build_certificate()
        keys2, req2, cert2 = self.build_certificate2()
        certificate = certs.create_certificate(req, (cert2, keys2), 1, (0, 10))
        self.assertIsNone(crypto.verify(
            cert2,
            certificate.to_cryptography().signature,
            certificate.to_cryptography().tbs_certificate_bytes,
            "sha256",
        ))

    def test_extensions(self):
        """Cert without declared extensions."""
        keys, req, cert = self.build_certificate(add_exts=False)
        # On an issued certificate, there's always authorityKeyIdentifier + subjectKeyIdentifier
        self.assertEqual(cert.get_extension_count(), 2)

    def test_extensions_extra(self):
        """Cert with an extra extension."""
        keys, req, cert = self.build_certificate(add_exts=True)
        # On an issued certificate, there's always authorityKeyIdentifier + subjectKeyIdentifier
        self.assertEqual(cert.get_extension_count(), 3)

    def test_validity(self):
        """Check the validity is the asked for."""
        keys, req, cert = self.build_certificate()
        now = datetime.now(pytz.utc) + timedelta(hours=1)
        self.assertGreater(now, utils.asn1_to_datetime(cert.get_notBefore()))
        self.assertLess(utils.asn1_to_datetime(cert.get_notAfter()), now)

    def test_validity_ca(self):
        """Check against CA validity."""
        keys, req, cert = self.build_certificate()
        keys2, req2, cert2 = self.build_certificate()
        self.assertRaises(
            CryptoException,
            certs.create_certificate,
            req, (cert2, keys2), 1, (-10, 4000),
        )
        self.assertRaises(
            CryptoException,
            certs.create_certificate,
            req, (cert2, keys2), 1, (0, 4000),
        )

class SelfSignedCertificate(TestCase):
    """create_self_signed"""
    def test_name(self):
        """Test the name and issuer."""
        name = [
            ('CN', 'test'),
            ('C', 'ES'),
            ('ST', 'test'),
            ('L', 'test'),
            ('O', 'test'),
            ('OU', 'test'),
            ('emailAddress', 'test@test.net'),
        ]
        key, cert = certs.create_self_signed(name)
        self.assertEqual(cert.get_subject(), cert.get_issuer())

class CACertificate(TestCase):
    """create_ca_certificate"""
    name = [
        ('CN', 'test'),
        ('C', 'ES'),
        ('ST', 'test'),
        ('L', 'test'),
        ('O', 'test'),
        ('OU', 'test'),
        ('emailAddress', 'test@test.net'),
    ]

    def test_create(self):
        """Test the name and issuer."""
        key, cert = certs.create_ca_certificate(self.name)
        self.assertEqual(cert.get_subject(), cert.get_issuer())

    def test_basic_constraints(self):
        """Test basicConstraints"""
        key, cert = certs.create_ca_certificate(self.name)
        ext = cert.get_extension(0)
        self.assertEqual(ext.get_short_name(), b'basicConstraints')
        self.assertTrue(ext.get_critical())
        self.assertEqual(ext.get_data(), b'0\x03\x01\x01\xff')

    def test_key_usage(self):
        """Test keyUsage"""
        key, cert = certs.create_ca_certificate(self.name)
        ext = cert.get_extension(1)
        self.assertEqual(ext.get_short_name(), b'keyUsage')
        self.assertTrue(ext.get_critical())
        self.assertEqual(ext.get_data(), b'\x03\x02\x01\x06')


    def test_pathlen(self):
        """Test pathlen"""
        key, cert = certs.create_ca_certificate(self.name, pathlen=2)
        ext = cert.get_extension(0)
        self.assertEqual(ext.get_short_name(), b'basicConstraints')
        self.assertTrue(ext.get_critical())
        self.assertEqual(ext.get_data(), b'0\x06\x01\x01\xff\x02\x01\x02') # last byte

class CRL(TestCase):
    """Test CRL creation"""
    revoked = [
        (1, datetime.now(pytz.utc), x509.ReasonFlags.unspecified),
    ]
    name = [
        ('CN', 'test'),
        ('C', 'ES'),
        ('ST', 'test'),
        ('L', 'test'),
        ('O', 'test'),
        ('OU', 'test'),
    ]

    def test_creation(self):
        """Test CRL creation."""
        ca_key, ca_cert = certs.create_ca_certificate(self.name, bits=512)
        ca_crl = crl.create_crl(self.revoked, 15, (ca_cert, ca_key), 1)
        self.assertIsInstance(ca_crl, crypto.CRL)

    def test_issuer(self):
        """Test CRL issuer."""
        ca_key, ca_cert = certs.create_ca_certificate(self.name, bits=512)
        ca_crl = crl.create_crl(self.revoked, 15, (ca_cert, ca_key), 1)
        self.assertEqual(ca_crl.get_issuer(), ca_cert.get_issuer())

    def test_revoked(self):
        """Test CRL issuer."""
        ca_key, ca_cert = certs.create_ca_certificate(self.name, bits=512)
        ca_crl = crl.create_crl(self.revoked, 15, (ca_cert, ca_key), 1)
        self.assertEqual(len(ca_crl.get_revoked()), 1)

    def test_revoked_empty(self):
        """Test CRL issuer."""
        ca_key, ca_cert = certs.create_ca_certificate(self.name, bits=512)
        ca_crl = crl.create_crl([], 15, (ca_cert, ca_key), 1)
        self.assertIsNone(ca_crl.get_revoked())

    def test_signature(self):
        """Test CRL issuer."""
        ca_key, ca_cert = certs.create_ca_certificate(self.name, bits=512)
        ca_crl = crl.create_crl([], 15, (ca_cert, ca_key), 1)
        self.assertIsNone(crypto.verify(
            ca_cert,
            ca_crl.to_cryptography().signature,
            ca_crl.to_cryptography().tbs_certlist_bytes,
            "sha256",
        ))
