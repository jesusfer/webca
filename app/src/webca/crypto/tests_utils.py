"""
Tests for util functions
"""
from datetime import datetime

import pytz
from django.test import TestCase
from pytz.reference import Pacific
from OpenSSL import crypto
from . import certs, utils
from . import constants as c
PEM = crypto.FILETYPE_PEM


def _create_pkcs12(priv, cert):
    pkey = crypto.load_privatekey(PEM, priv)
    x509 = crypto.load_certificate(PEM, cert)
    pkcs12 = crypto.PKCS12()
    pkcs12.set_certificate(x509)
    pkcs12.set_privatekey(pkey)
    return pkcs12


class Utils(TestCase):
    """Test class for util functions"""
    def test_new_serial(self):
        """new_serial"""
        serial = utils.new_serial()
        self.assertGreater(serial, 0)
        self.assertLess(serial, 1 << 160)

    def test_int_to_hex(self):
        """int_to_hex"""
        self.assertEqual('75bcd15', utils.int_to_hex(123456789))

    def test_name_to_components(self):
        """name_to_components"""
        name = [
            ('CN', 'test'),
            ('C', 'ES'),
            ('ST', 'test'),
            ('L', 'test'),
            ('O', 'test'),
            ('OU', 'test'),
        ]
        c = utils.name_to_components('/CN=test/C=ES/ST=test/L=test/O=test/OU=test')
        self.assertEqual(c, name)

    def test_name_to_components_empty(self):
        """name_to_components"""
        self.assertCountEqual(utils.name_to_components(''), [])

    def test_components_to_name(self):
        """components_to_name"""
        name = [
            ('CN', 'test'),
            ('C', 'ES'),
            ('ST', 'test'),
            ('L', 'test'),
            ('O', 'test'),
            ('OU', 'test'),
        ]
        c = utils.components_to_name(name)
        self.assertEqual(c, '/CN=test/C=ES/ST=test/L=test/O=test/OU=test')

    def test_components_to_name_empty(self):
        """components_to_name"""
        self.assertCountEqual(utils.components_to_name([]), '')

    def test_components_to_name_one(self):
        """components_to_name"""
        self.assertCountEqual(
            utils.components_to_name([('CN', 'test')]),
            '/CN=test',
        )

    def test_components_to_name_bytes(self):
        """components_to_name"""
        self.assertCountEqual(
            utils.components_to_name([(b'CN', b'test')]),
            '/CN=test',
        )

    def test_datetime_to_asn1(self):
        """datetime_to_asn1"""
        when = datetime(2018, 5, 27, 12, 34, 56)
        asn1 = utils.datetime_to_asn1(when)
        self.assertEqual(asn1, b'20180527123456Z')
        when = datetime(2018, 5, 27, 12, 34, 56, tzinfo=Pacific)
        asn1 = utils.datetime_to_asn1(when)
        self.assertEqual(asn1, b'20180527123456-0700')

    def test_private_key_pkey(self):
        """Test private key type - RSA"""
        priv = """-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAybxDeYLbbriv2wJ2
d0w09xGJdi7dIzgPtI6beSKkk3ILXRqj59ufj/i7RXg7RASOzZH/wmfvbBNsI5y5
M62FDwIDAQABAkB/ayvrKd3TV0+rsyiEPVwO2cLLJNqEDjrNPm2w21K71WMVkngm
OH0DpFePpPHQf+EdUfpRwZNdXhyt52MxC4GxAiEA8FBZd1uqZ1PGrkety7EGgEJk
BTrtu/WVLbGhbloNvr0CIQDW50RfhAmFJPh6bo4nKE/qtz5O0BVsoFQA8l7uB+eF
uwIgC57HBLeBAOgTJmA+7ieMOe176qjT0A/q+7+oH67pFT0CIQDInpuAw6WTi2EA
AsdoHMUGbEyZjL4Da2UggSNH+U8U0wIgR1ZLchEpsHafverbte2qHey/BSHyKEQi
cCn1I7EnAH8=
-----END PRIVATE KEY-----"""
        key = crypto.load_privatekey(PEM, priv)
        self.assertEqual(utils.private_key_type(key), c.KEY_RSA)

    def test_private_key_rsa(self):
        """Test private key type - RSA"""
        priv = """-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAybxDeYLbbriv2wJ2
d0w09xGJdi7dIzgPtI6beSKkk3ILXRqj59ufj/i7RXg7RASOzZH/wmfvbBNsI5y5
M62FDwIDAQABAkB/ayvrKd3TV0+rsyiEPVwO2cLLJNqEDjrNPm2w21K71WMVkngm
OH0DpFePpPHQf+EdUfpRwZNdXhyt52MxC4GxAiEA8FBZd1uqZ1PGrkety7EGgEJk
BTrtu/WVLbGhbloNvr0CIQDW50RfhAmFJPh6bo4nKE/qtz5O0BVsoFQA8l7uB+eF
uwIgC57HBLeBAOgTJmA+7ieMOe176qjT0A/q+7+oH67pFT0CIQDInpuAw6WTi2EA
AsdoHMUGbEyZjL4Da2UggSNH+U8U0wIgR1ZLchEpsHafverbte2qHey/BSHyKEQi
cCn1I7EnAH8=
-----END PRIVATE KEY-----"""
        cert = """-----BEGIN CERTIFICATE-----
MIIBjTCCATegAwIBAgIJAMLQYSpm+vm9MA0GCSqGSIb3DQEBCwUAMCIxEDAOBgNV
BAMMB1JTQSA1MTIxDjAMBgNVBAoMBVdlYkNBMB4XDTE4MDUyNzEwMjAzOFoXDTE4
MDYyNjEwMjAzOFowIjEQMA4GA1UEAwwHUlNBIDUxMjEOMAwGA1UECgwFV2ViQ0Ew
XDANBgkqhkiG9w0BAQEFAANLADBIAkEAybxDeYLbbriv2wJ2d0w09xGJdi7dIzgP
tI6beSKkk3ILXRqj59ufj/i7RXg7RASOzZH/wmfvbBNsI5y5M62FDwIDAQABo1Aw
TjAdBgNVHQ4EFgQUkaOkLIQe2hh8dGQFm+iSY/hjQucwHwYDVR0jBBgwFoAUkaOk
LIQe2hh8dGQFm+iSY/hjQucwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAANB
AL89kRbdtpdFo+nKxRWc6Dx72jbEX3nNBsxjVIHbm8RjFQ9ASwr6szqJjmROCXcF
IJrZsa9U1KVUZBvzrhZrOCE=
-----END CERTIFICATE-----"""
        pkcs12 = _create_pkcs12(priv, cert)
        self.assertEqual(utils.private_key_type(pkcs12), c.KEY_RSA)

    def test_private_key_dsa(self):
        """Test private key type - DSA"""
        priv = """-----BEGIN DSA PRIVATE KEY-----
MIH4AgEAAkEAnogScrza9M5nFogjwu7MUSgOeWRfHSFWKLiFxfkNOAb1Z5oXTUKR
cKdSxfI1zu47rvyqV6+4SSkQEsVJ2/7DQQIVANuQv4L3sp8AiUn+mwCyXhedQl2Z
AkBfCDLU4nx7OeMx+vD9MN7FW57pHm/43B1Tu/cUOWcp5VHPJRuVWJqINIteY/0i
lFEUCMibgol8Upj6CGnuDpvTAkAbnRx76A8r+o/3I5hlrlAmCi68uiiqW6W2R40U
2g/KlIiafMEQ3+OrMwwkPX0aaJwa8m7lsUlmhhYOXu5p4fL1AhUAuxjeo0++fjI+
nEIPmnCNPGjuBY8=
-----END DSA PRIVATE KEY-----"""
        cert = """-----BEGIN CERTIFICATE-----
MIICDjCCAcqgAwIBAgIJAMcdoiKyV98cMAsGCWCGSAFlAwQDAjAiMRAwDgYDVQQD
DAdEU0EgNTEyMQ4wDAYDVQQKDAVXZWJDQTAeFw0xODA1MjcxMDI1MjBaFw0xODA2
MjYxMDI1MjBaMCIxEDAOBgNVBAMMB0RTQSA1MTIxDjAMBgNVBAoMBVdlYkNBMIHw
MIGoBgcqhkjOOAQBMIGcAkEAnogScrza9M5nFogjwu7MUSgOeWRfHSFWKLiFxfkN
OAb1Z5oXTUKRcKdSxfI1zu47rvyqV6+4SSkQEsVJ2/7DQQIVANuQv4L3sp8AiUn+
mwCyXhedQl2ZAkBfCDLU4nx7OeMx+vD9MN7FW57pHm/43B1Tu/cUOWcp5VHPJRuV
WJqINIteY/0ilFEUCMibgol8Upj6CGnuDpvTA0MAAkAbnRx76A8r+o/3I5hlrlAm
Ci68uiiqW6W2R40U2g/KlIiafMEQ3+OrMwwkPX0aaJwa8m7lsUlmhhYOXu5p4fL1
o1AwTjAdBgNVHQ4EFgQUHub1qPkaKCtkQbmu3RnLaa8QAP4wHwYDVR0jBBgwFoAU
Hub1qPkaKCtkQbmu3RnLaa8QAP4wDAYDVR0TBAUwAwEB/zALBglghkgBZQMEAwID
MQAwLgIVAMOEZCvJoNjIMzbH0yWrEUS6IxywAhUAzDhkGKvAH1V3o2ZsJsIotFUk
IiQ=
-----END CERTIFICATE-----"""
        pkcs12 = _create_pkcs12(priv, cert)
        self.assertEqual(utils.private_key_type(pkcs12), c.KEY_DSA)

    def test_private_key_ec(self):
        """Test private key type - EC"""
        priv = """-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJZ57L6f6ywtZa7VhsvthAShxjdrL9EIrVwVgxnmD5b3oAoGCCqGSM49
AwEHoUQDQgAEIg6eBOPv5M2z4ANtsJukbimKWX04lanEdALsbu2xNCDBXJ0IJ4Sd
3u4G1qvrKX0mBHd7yUPGui+7bvp084mNag==
-----END EC PRIVATE KEY-----"""
        cert = """-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIJAINtiwRC4eBJMAoGCCqGSM49BAMCMCExDzANBgNVBAMM
BkVDIDI1NjEOMAwGA1UECgwFV2ViQ0EwHhcNMTgwNTI3MTAyNTIyWhcNMTgwNjI2
MTAyNTIyWjAhMQ8wDQYDVQQDDAZFQyAyNTYxDjAMBgNVBAoMBVdlYkNBMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEIg6eBOPv5M2z4ANtsJukbimKWX04lanEdALs
bu2xNCDBXJ0IJ4Sd3u4G1qvrKX0mBHd7yUPGui+7bvp084mNaqNQME4wHQYDVR0O
BBYEFEmE51rEUz4TuD8oEAw2lvMfvi6LMB8GA1UdIwQYMBaAFEmE51rEUz4TuD8o
EAw2lvMfvi6LMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgfiKDoHB3
WzRO1juSMyVBuBw2p1o0ab+3fBNDvff8PXcCIQCUKIyzTnM7Wz6TkABfqOcmx7n4
sbRvdOg3CepLGW3Ytw==
-----END CERTIFICATE-----"""
        pkcs12 = _create_pkcs12(priv, cert)
        self.assertEqual(utils.private_key_type(pkcs12), c.KEY_EC)

    def test_public_key_rsa(self):
        """Test public key type - RSA"""
        cert = """-----BEGIN CERTIFICATE-----
MIIBjTCCATegAwIBAgIJAMLQYSpm+vm9MA0GCSqGSIb3DQEBCwUAMCIxEDAOBgNV
BAMMB1JTQSA1MTIxDjAMBgNVBAoMBVdlYkNBMB4XDTE4MDUyNzEwMjAzOFoXDTE4
MDYyNjEwMjAzOFowIjEQMA4GA1UEAwwHUlNBIDUxMjEOMAwGA1UECgwFV2ViQ0Ew
XDANBgkqhkiG9w0BAQEFAANLADBIAkEAybxDeYLbbriv2wJ2d0w09xGJdi7dIzgP
tI6beSKkk3ILXRqj59ufj/i7RXg7RASOzZH/wmfvbBNsI5y5M62FDwIDAQABo1Aw
TjAdBgNVHQ4EFgQUkaOkLIQe2hh8dGQFm+iSY/hjQucwHwYDVR0jBBgwFoAUkaOk
LIQe2hh8dGQFm+iSY/hjQucwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAANB
AL89kRbdtpdFo+nKxRWc6Dx72jbEX3nNBsxjVIHbm8RjFQ9ASwr6szqJjmROCXcF
IJrZsa9U1KVUZBvzrhZrOCE=
-----END CERTIFICATE-----"""
        x509 = crypto.load_certificate(PEM, cert)
        self.assertEqual(utils.public_key_type(x509), c.KEY_RSA)

    def test_public_key_dsa(self):
        """Test public key type - DSA"""
        cert = """-----BEGIN CERTIFICATE-----
MIICDjCCAcqgAwIBAgIJAMcdoiKyV98cMAsGCWCGSAFlAwQDAjAiMRAwDgYDVQQD
DAdEU0EgNTEyMQ4wDAYDVQQKDAVXZWJDQTAeFw0xODA1MjcxMDI1MjBaFw0xODA2
MjYxMDI1MjBaMCIxEDAOBgNVBAMMB0RTQSA1MTIxDjAMBgNVBAoMBVdlYkNBMIHw
MIGoBgcqhkjOOAQBMIGcAkEAnogScrza9M5nFogjwu7MUSgOeWRfHSFWKLiFxfkN
OAb1Z5oXTUKRcKdSxfI1zu47rvyqV6+4SSkQEsVJ2/7DQQIVANuQv4L3sp8AiUn+
mwCyXhedQl2ZAkBfCDLU4nx7OeMx+vD9MN7FW57pHm/43B1Tu/cUOWcp5VHPJRuV
WJqINIteY/0ilFEUCMibgol8Upj6CGnuDpvTA0MAAkAbnRx76A8r+o/3I5hlrlAm
Ci68uiiqW6W2R40U2g/KlIiafMEQ3+OrMwwkPX0aaJwa8m7lsUlmhhYOXu5p4fL1
o1AwTjAdBgNVHQ4EFgQUHub1qPkaKCtkQbmu3RnLaa8QAP4wHwYDVR0jBBgwFoAU
Hub1qPkaKCtkQbmu3RnLaa8QAP4wDAYDVR0TBAUwAwEB/zALBglghkgBZQMEAwID
MQAwLgIVAMOEZCvJoNjIMzbH0yWrEUS6IxywAhUAzDhkGKvAH1V3o2ZsJsIotFUk
IiQ=
-----END CERTIFICATE-----"""
        x509 = crypto.load_certificate(PEM, cert)
        self.assertEqual(utils.public_key_type(x509), c.KEY_DSA)

    def test_public_key_ec(self):
        """Test public key type - EC"""
        cert = """-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIJAINtiwRC4eBJMAoGCCqGSM49BAMCMCExDzANBgNVBAMM
BkVDIDI1NjEOMAwGA1UECgwFV2ViQ0EwHhcNMTgwNTI3MTAyNTIyWhcNMTgwNjI2
MTAyNTIyWjAhMQ8wDQYDVQQDDAZFQyAyNTYxDjAMBgNVBAoMBVdlYkNBMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEIg6eBOPv5M2z4ANtsJukbimKWX04lanEdALs
bu2xNCDBXJ0IJ4Sd3u4G1qvrKX0mBHd7yUPGui+7bvp084mNaqNQME4wHQYDVR0O
BBYEFEmE51rEUz4TuD8oEAw2lvMfvi6LMB8GA1UdIwQYMBaAFEmE51rEUz4TuD8o
EAw2lvMfvi6LMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgfiKDoHB3
WzRO1juSMyVBuBw2p1o0ab+3fBNDvff8PXcCIQCUKIyzTnM7Wz6TkABfqOcmx7n4
sbRvdOg3CepLGW3Ytw==
-----END CERTIFICATE-----"""
        x509 = crypto.load_certificate(PEM, cert)
        self.assertEqual(utils.public_key_type(x509), c.KEY_EC)

    def test_public_key_req(self):
        """Test public key type - EC"""
        csr = """-----BEGIN CERTIFICATE REQUEST-----
MIHcMIGDAgEAMCExDzANBgNVBAMMBkVDIDI1NjEOMAwGA1UECgwFV2ViQ0EwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQiDp4E4+/kzbPgA22wm6RuKYpZfTiVqcR0
Auxu7bE0IMFcnQgnhJ3e7gbWq+spfSYEd3vJQ8a6L7tu+nTziY1qoAAwCgYIKoZI
zj0EAwIDSAAwRQIhAMRpKf1c6Z0qgTCNxyKXZGsc4i/qxfqxzcZ/QK7Ot9TeAiA7
APUerdBAf4HdigxiwcckjZ8TG1snkyp/qVuMhxSDEg==
-----END CERTIFICATE REQUEST-----"""
        x509req = crypto.load_certificate_request(PEM, csr)
        self.assertEqual(utils.public_key_type(x509req), c.KEY_EC)

class KeyUsage(TestCase):

    def test_rsa(self):
        """Test key type and key usage match - EE RSA."""
        key = c.KEY_RSA
        usage = [
            c.KU_DIGITALSIGNATURE,
            c.KU_NONREPUDIATION,
            c.KU_KEYENCIPHERMENT,
            c.KU_DATAENCIPHERMENT,
        ]
        self.assertTrue(utils.check_key_usage(key, usage))

    def test_rsa_ca(self):
        """Test key type and key usage match - CA RSA."""
        key = c.KEY_RSA
        usage = [
            c.KU_DIGITALSIGNATURE,
            c.KU_NONREPUDIATION,
            c.KU_KEYENCIPHERMENT,
            c.KU_DATAENCIPHERMENT,
            c.KU_KEYCERTSIGN,
            c.KU_CRLSIGN,
        ]
        self.assertTrue(utils.check_key_usage(key, usage, True))

    def test_rsa_no(self):
        """Test key type and key usage match - EE RSA."""
        key = c.KEY_RSA
        usage = [
            c.KU_KEYAGREEMENT,
            c.KU_ENCIPHERONLY,
            c.KU_DECIPHERONLY,
        ]
        self.assertFalse(utils.check_key_usage(key, usage))

    def test_rsa_ca_no(self):
        """Test key type and key usage match - CA RSA."""
        key = c.KEY_RSA
        usage = [
            c.KU_KEYAGREEMENT,
            c.KU_ENCIPHERONLY,
            c.KU_DECIPHERONLY,
        ]
        self.assertFalse(utils.check_key_usage(key, usage, True))

    def test_dsa(self):
        """Test key type and key usage match - EE DSA."""
        key = c.KEY_DSA
        usage = [
            c.KU_DIGITALSIGNATURE,
            c.KU_NONREPUDIATION,
        ]
        self.assertTrue(utils.check_key_usage(key, usage))

    def test_dsa_ca(self):
        """Test key type and key usage match - CA DSA."""
        key = c.KEY_DSA
        usage = [
            c.KU_DIGITALSIGNATURE,
            c.KU_NONREPUDIATION,
            c.KU_KEYCERTSIGN,
            c.KU_CRLSIGN,
        ]
        self.assertTrue(utils.check_key_usage(key, usage, True))

    def test_dsa_no(self):
        """Test key type and key usage match - EE DSA."""
        key = c.KEY_DSA
        usage = [
            c.KU_KEYENCIPHERMENT,
            c.KU_DATAENCIPHERMENT,
            c.KU_KEYAGREEMENT,
            c.KU_ENCIPHERONLY,
            c.KU_DECIPHERONLY,
        ]
        self.assertFalse(utils.check_key_usage(key, usage))

    def test_dsa_ca_no(self):
        """Test key type and key usage match - CA DSA."""
        key = c.KEY_DSA
        usage = [
            c.KU_KEYENCIPHERMENT,
            c.KU_DATAENCIPHERMENT,
            c.KU_KEYAGREEMENT,
            c.KU_ENCIPHERONLY,
            c.KU_DECIPHERONLY,
        ]
        self.assertFalse(utils.check_key_usage(key, usage, True))

    def test_ec(self):
        """Test key type and key usage match - EE EC."""
        key = c.KEY_EC
        usage = [
            c.KU_DIGITALSIGNATURE,
            c.KU_NONREPUDIATION,
            c.KU_KEYAGREEMENT,
            c.KU_ENCIPHERONLY,
            c.KU_DECIPHERONLY,
        ]
        self.assertTrue(utils.check_key_usage(key, usage))

    def test_ec_ca(self):
        """Test key type and key usage match - EE EC."""
        key = c.KEY_EC
        usage = [
            c.KU_DIGITALSIGNATURE,
            c.KU_NONREPUDIATION,
            c.KU_KEYAGREEMENT,
            c.KU_ENCIPHERONLY,
            c.KU_DECIPHERONLY,
            c.KU_KEYCERTSIGN,
            c.KU_CRLSIGN,
        ]
        self.assertTrue(utils.check_key_usage(key, usage, True))

    def test_ec_no(self):
        """Test key type and key usage match - EE EC."""
        key = c.KEY_EC
        usage = [
            c.KU_KEYENCIPHERMENT,
            c.KU_DATAENCIPHERMENT,
        ]
        self.assertFalse(utils.check_key_usage(key, usage))

    def test_ec_ca_no(self):
        """Test key type and key usage match - EE EC."""
        key = c.KEY_EC
        usage = [
            c.KU_KEYENCIPHERMENT,
            c.KU_DATAENCIPHERMENT,
        ]
        self.assertFalse(utils.check_key_usage(key, usage, True))
