#pylint: disable=C0103
from OpenSSL import crypto

from webca.certstore import *
from webca.crypto import *
from webca.crypto.utils import *

store = CertStore.get_store('9a16e500-cc97-48e4-9b62-4e41d91c2607')

# Create CSR Sign
# root_name = [
#     ('CN', 'CSR Sign'),
# ]
# root_key, root_cert = create_ca_certificate(root_name, 512)
# issuer_root = (root_cert, root_key)

# store.add_certificate(root_key, root_cert)

# exit()

# Create Root CA
root_name = [
    ('CN', 'CA Test'),
    ('C', 'es'),
    ('ST', 'Madrid'),
]
root_key, root_cert = create_ca_certificate(
    root_name,
    512,
    duration=5*365*24*3600,
)
issuer_root = (root_cert, root_key)

# store.add_certificate(root_key, root_cert)

# print_certificate(root_cert)
# print(export_private_key(root_key))
# print(export_public_key(root_key))
# print(export_certificate(root_cert))

# Create Intermediate CA
inter_name = [('CN', 'CA Test Intermediate'), ]
inter_key, inter_cert = create_ca_certificate(
    inter_name,
    512,
    pathlen=0,
    duration=2*365*24*3600,
    signing_cert=issuer_root
)
issuer_inter = (inter_cert, inter_key)
# store.add_certificate(inter_key, inter_cert)

# print_certificate(inter_cert)
# print(export_private_key(inter_key))
# print(export_public_key(inter_key))
# print(export_certificate(inter_cert))

# Create web server certificate
server_name = [('CN', 'www.test.net'), ]

#pylint: disable=e1101
ku = KeyUsage().digitalSignature().keyEncipherment().value().encode('ascii')
eku = ExtendedKeyUsage().serverAuth().clientAuth(
).codeSigning().value().encode('ascii')
#pylint: enable=e1101
server_extensions = [
    crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE'),
    crypto.X509Extension(b'keyUsage', True, ku),
    crypto.X509Extension(b'extendedKeyUsage', False, eku),
    crypto.X509Extension(b'subjectAltName', False, b'DNS:www.test.net'),
    crypto.X509Extension(b'crlDistributionPoints', False,
                         b'URI:http://test.net/test.crl'),
    crypto.X509Extension(b'1.6.6', False, b'DER:31:32:33')
]
server_key = create_key_pair(crypto.TYPE_RSA, 512)
server_req = create_cert_request(
    server_key,
    server_name,
    server_extensions,
)
server_cert = create_certificate(
    server_req,
    issuer_inter,
    new_serial(),
    (0, 3600),
)

# store.add_certificate(server_key, server_cert)

# print_certificate(server_cert)
# print(export_certificate(server_cert))

# rev = revoke_certificate(server_cert)
# crl = create_crl([rev], 14, issuer_root)

rev = [
    (server_cert.get_serial_number(), datetime.now(pytz.utc), 'superseded'),
]
crl = create_crl(
    revoked_list=rev,
    days=14,
    issuer=issuer_root,
    number=1,
    # is_delta=True,
    # delta_number=2,
    # crl_locations=['http://here'],
)
print_crl(crl)
