"""
Test the OCSP responder.
"""
from base64 import b64encode
from urllib.parse import quote

from asn1crypto.ocsp import OCSPRequest, OCSPResponse, TBSRequest
from django.test import TestCase


def build_request_good():
    tbs_request = TBSRequest({
        'request_list': [
            {
                'req_cert': {
                    'hash_algorithm': {
                        'algorithm': 'sha1'
                    },
                    'issuer_name_hash': b'379276ADE1846D5A1D184BC135A2D3D23B221DA2',
                    'issuer_key_hash': b'C7BA089932AE7ABE29D136723E5FF49F480F68F3',
                    'serial_number': 221578034377984887419532563643305653706,
                },
                'single_request_extensions': []
            }
        ],
        'request_extensions': []
    })
    ocsp = OCSPRequest({
        'tbs_request': tbs_request,
        'optional_signature': None
    })
    return ocsp

def build_request_revoked():
    tbs_request = TBSRequest({
        'request_list': [
            {
                'req_cert': {
                    'hash_algorithm': {
                        'algorithm': 'sha1'
                    },
                    'issuer_name_hash': b'379276ADE1846D5A1D184BC135A2D3D23B221DA2',
                    'issuer_key_hash': b'C7BA089932AE7ABE29D136723E5FF49F480F68F3',
                    'serial_number': 43335495160811514204812512316928417740,
                },
                'single_request_extensions': []
            }
        ],
        'request_extensions': []
    })
    ocsp = OCSPRequest({
        'tbs_request': tbs_request,
        'optional_signature': None
    })
    return ocsp

class OCSP(TestCase):
    """Test the OCSP responder."""
    fixtures = [
        # 'initial',
        'config',
        'certstore_db',
    ]
    multi_db = True

    def test_get_empty(self):
        """Empty GET."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        ocsp = OCSPResponse.load(response.content)
        self.assertEqual(ocsp.native['response_status'], 'malformed_request')

    def test_get_slug_invalid(self):
        """Invalid GET request."""
        response = self.client.get('/something')
        self.assertEqual(response.status_code, 200)
        ocsp = OCSPResponse.load(response.content)
        self.assertEqual(ocsp.native['response_status'], 'malformed_request')

    def test_get(self):
        """Valid GET request."""
        ocsp = build_request_good()
        body = quote(b64encode(ocsp.dump()).decode('utf8'))
        response = self.client.get('/' + body)
        self.assertEqual(response.status_code, 200)
        ocsp = OCSPResponse.load(response.content)
        self.assertEqual(ocsp.native['response_status'], 'successful')

    def test_post_revoked(self):
        """Valid POST request."""
        ocsp = build_request_revoked()
        response = self.client.post('/', data=ocsp.dump(), content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        ocsp = OCSPResponse.load(response.content)
        self.assertEqual(ocsp.native['response_status'], 'successful')

    def test_post_good(self):
        """Valid POST request."""
        ocsp = build_request_good()
        response = self.client.post('/', data=ocsp.dump(), content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        ocsp = OCSPResponse.load(response.content)
        self.assertEqual(ocsp.native['response_status'], 'successful')
