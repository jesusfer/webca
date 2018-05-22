
import traceback
from base64 import b64decode
from datetime import datetime

from asn1crypto.ocsp import OCSPRequest
from asn1crypto.util import timezone
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ocspbuilder import OCSPResponseBuilder
from oscrypto import asymmetric

from webca.certstore import CertStore
from webca.config import constants as p
from webca.config.models import ConfigurationObject as Config
from webca.crypto import constants as c
from webca.crypto import utils as crypto_utils
from webca.web.models import Certificate, Revoked

# Missing: revoked, remove_from_crl, privilege_withdrawn
REASONS = {
    c.REV_UNSPECIFIED: 'revoked',
    c.REV_KEYCOMPROMISE: 'key_compromise',
    c.REV_CACOMPROMISE: 'ca_compromise',
    c.REV_AFFILIATIONCHANGED: 'affiliation_changed',
    c.REV_SUPERSEDED: 'superseded',
    c.REV_CESSATIONOFOPERATION: 'cessation_of_operation',
    c.REV_CERTIFICATEHOLD: 'certificate_hold',
}


@method_decorator(csrf_exempt, name='dispatch')
class OCSPResponder(View):
    """OCSP Responder.

    An HTTP-based OCSP response is composed of the appropriate HTTP
    headers, followed by the binary value of the DER encoding of the
    OCSPResponse.  The Content-Type header has the value
    "application/ocsp-response".  The Content-Length header SHOULD
    specify the length of the response.  Other HTTP headers MAY be
    present and MAY be ignored if not understood by the requestor.

    pip install asn1crypto
    pip install ocspbuilder
    """

    def __init__(self, *args, **kwargs):
        """Setup the signing certificate."""
        # TODO: the cert must have the EKU of OCSPSigning and cannot be self signed
        key_store, keysign_serial = Config.get_value(p.CERT_KEYSIGN).split(',')
        if not keysign_serial:
            raise ValueError('No CA certificate configured.')
        store = CertStore.get_store(key_store)

        ca_x509 = store.get_certificate(keysign_serial)
        if not ca_x509:
            raise ValueError('The CA certificates are not correctly configured.')
        ca_x509_der = crypto_utils.export_certificate(ca_x509, pem=False)
        self.issuer_cert = asymmetric.load_certificate(ca_x509_der)

        # ca_key = store.get_private_key(keysign_serial)
        # if not ca_key:
            # raise ValueError('Cannot find the CA key.')
        # ca_key_der = crypto_utils.export_private_key(ca_key, pem=False)
        # self.issuer_key = asymmetric.load_private_key(ca_key_der)

        key_store, ocspsign_serial = Config.get_value(p.CERT_OCSPSIGN).split(',')
        if not ocspsign_serial:
            raise ValueError('No OCSP certificate configured.')
        store = CertStore.get_store(key_store)

        ocsp_key = store.get_private_key(ocspsign_serial)
        if not ocsp_key:
            raise ValueError('Cannot find the OCSP key')
        ocsp_key_der = crypto_utils.export_private_key(ocsp_key, pem=False)
        self.ocsp_key = asymmetric.load_private_key(ocsp_key_der)

        ocsp_x509 = store.get_certificate(ocspsign_serial)
        if not ocsp_x509:
            raise ValueError('Cannot find the OCSP certificate')
        ocsp_x509_der = crypto_utils.export_certificate(ocsp_x509, pem=False)
        self.ocsp_cert = asymmetric.load_certificate(ocsp_x509_der)

    def get(self, request, *args, **kwargs):
        """
        An OCSP request using the GET method is constructed as follows:

        GET {url}/{url-encoding of base-64 encoding of the DER encoding of
        the OCSPRequest}

        where {url} may be derived from the value of the authority
        information access extension in the certificate being checked for
        revocation, or other local configuration of the OCSP client.
        """
        slug = kwargs.pop('slug', '')
        if not slug:
            return HttpResponseBadRequest()
        try:
            return self.process_ocsp_request(request, b64decode(slug))
        except ValueError as error:
            print('OCSP Responder error: %s' % error)
            # traceback.print_exc(error)
            return self._ocsp_error('internal_error')

    def post(self, request, *args, **kwargs):
        """
        An OCSP request using the POST method is constructed as follows: The
        Content-Type header has the value "application/ocsp-request", while
        the body of the message is the binary value of the DER encoding of
        the OCSPRequest.

        The Content-Type header has the value "application/ocsp-response"
        """
        try:
            return self.process_ocsp_request(request, request.body)
        except ValueError as error:
            print('OCSP Responder error: %s' % error)
            # traceback.print_exc(error)
            return self._ocsp_error('internal_error')

    def process_ocsp_request(self, request, raw):
        """
        Response types:
            'successful',
            'malformed_request',
            'internal_error',
            'try_later',
            'sign_required',
            'unauthorized'
        """
        ocsp = OCSPRequest.load(raw)
        # FUTURE: check the issuer key hash to make sure it's for us
        # FUTURE: responses may be cached too
        questions = []
        for request in ocsp.native['tbs_request']['request_list']:
            serial = request['req_cert']['serial_number']
            cert = Revoked.objects.filter(certificate__serial=serial).first()
            if cert:
                questions.append((serial, cert))
            else:
                questions.append((serial, None))
        if questions:
            for serial, revoked in questions:
                # FIXME: We can only respond to one cert, we need to use asn1crypto.ocsp for several responses
                if not revoked:
                    cert = Certificate.objects.filter(serial=serial).first()
                    if not cert:
                        # FIXME: To return unknown we need to pass the cert details.
                        # builder = OCSPResponseBuilder('successful', None, 'unknown')
                        return self._ocsp_error('internal_error')
                    else:
                        der = crypto_utils.export_certificate(cert.get_certificate(), pem=False)
                        subject_cert = asymmetric.load_certificate(der)
                        builder = OCSPResponseBuilder('successful', subject_cert, 'good')
                    # This if there is a OCSP signing certificate
                else:
                    der = crypto_utils.export_certificate(revoked.certificate.get_certificate(), pem=False)
                    subject_cert = asymmetric.load_certificate(der)
                    revocation_date = revoked.date
                    reason = REASONS[revoked.reason]
                    builder = OCSPResponseBuilder('successful', subject_cert, reason, revocation_date)
                builder.certificate_issuer = self.issuer_cert
                ocsp_response = builder.build(self.ocsp_key, self.ocsp_cert)
                # FUTURE: cache this so it doesn't have to be loaded every time
                return HttpResponse(ocsp_response.dump())
        # Didn't get any serial??
        return self._ocsp_error('malformed_request')

    def _ocsp_error(self, error):
        """Return an `error` OCSPResponse."""
        builder = OCSPResponseBuilder(error)
        ocsp_response = builder.build(self.ocsp_key, self.ocsp_cert)
        return HttpResponse(ocsp_response.dump())
