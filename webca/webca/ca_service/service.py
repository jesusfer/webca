"""
Implementation of the CA service.
"""
import time
from datetime import datetime, timedelta

import pytz
from django.db.models import Q

from webca.certstore import CertStore
from webca.config import constants as parameters
from webca.config.models import ConfigurationObject as Config
from webca.crypto import utils as cert_utils
from webca.crypto import certs
from webca.crypto.extensions import build_san, build_crl
from webca.web.models import Certificate, Request, CRLLocation


class CAService:
    """Polling service that processes requests from end users."""

    pending_requests = Q(status=Request.STATUS_PROCESSING) & Q(approved=True)

    # Initialization and service

    #pylint: disable=w0613
    def __init__(self, *args, **kwargs):
        # Get the current certificates
        self.set_certificates()

    def set_certificates(self):
        """Set up the signing certificates."""
        key_store, keysign_serial = Config.get_value(
            parameters.CERT_KEYSIGN).split(',')
        crl_store, crlsign_serial = Config.get_value(
            parameters.CERT_KEYSIGN).split(',')
        csr_store, csrsign_serial = Config.get_value(
            parameters.CERT_CSRSIGN).split(',')

        if not keysign_serial or not crlsign_serial or not csrsign_serial:
            self.fatal_error('No CA certificates configured.')
        store = CertStore.get_store(key_store)
        self.certsign = (
            store.get_certificate(keysign_serial),
            store.get_private_key(keysign_serial),
        )
        store = CertStore.get_store(crl_store)
        self.crlsign = (
            store.get_certificate(crlsign_serial),
            store.get_private_key(crlsign_serial),
        )
        store = CertStore.get_store(csr_store)
        self.csrsign = (
            store.get_certificate(csrsign_serial),
            store.get_private_key(csrsign_serial),
        )

    def run(self):
        """Start the service."""
        try:
            print('CA service started')
            self._run()
        except KeyboardInterrupt:
            print('Exiting...')

    def _run(self):
        """Really run the service."""
        while True:
            time.sleep(0.5)
            self._process_requests(
                Request.objects.filter(self.pending_requests))

    # Output and control

    def fatal_error(self, message):
        """Print a message and exit."""
        print(message)
        exit(-2)

    # The stuff

    def _process_requests(self, requests):
        """Process a list of requests that have been approved."""
        if requests:
            self.set_certificates()
        for request in requests:
            print('Got a certificate request ({})!'.format(request.id))
            try:
                self._process_request(request)
            except Exception as ex:
                raise ex

    def _process_request(self, request):
        """To process a request we have to:
        1. Get the public key from the CSR
        2. Get the requested subject from the Request
        3. Get the template used from the Request
        4. Validate input
        5. Build the certificate using 1+2+3
        6. Sign the certificate
        7. Save the certificate
        8. Update the request
        """
        try:
            request.certificate
            # if the above succeeds, then there certificate was already issued
            request.status = Request.STATUS_ISSUED
            request.save()
            return
        except Certificate.DoesNotExist:
            print('Issuing... ', end='')
        # Get the public key and subject from the user's CSR and the request
        pub_key = request.get_csr().get_pubkey()
        subject = cert_utils.name_to_components(request.subject)
        # Get the fixed extensions from the template
        extensions = request.template.get_extensions()
        # If there's a SAN, add it here
        if request.san:
            san = build_san(request.san)
            extensions.append(san)
        # TODO: Now build the CRL extension.
        crl_locations = CRLLocation.get_locations()
        if crl_locations:
            crl = build_crl(crl_locations.values_list('url', flat=True))
            extensions.append(crl)

        # Validate stuff
        # Key size. Template requirements might have changed since the request was done
        if pub_key.bits() < request.template.min_bits:
            # The request at this point will never meet the template minimum
            # so it should be rejected
            request.status = Request.STATUS_REJECTED
            request.reject_reason = 'The key does not meet the required minimum size: size={} required={}'.format(
                pub_key.bits(),
                request.template.min_bits)
            request.save()
            return

        # New stuff
        serial = cert_utils.new_serial()
        valid_from = 0
        valid_to = int(timedelta(days=request.template.days).total_seconds())
        # Generate CSR and then the certificate
        new_csr = certs.create_cert_request(
            pub_key,
            name=subject,
            extensions=extensions,
            signing_key=self.csrsign[1]
        )
        x509 = certs.create_certificate(
            new_csr,
            self.certsign,
            serial,
            (valid_from, valid_to)
        )

        # Save the new certificate
        certificate = Certificate()
        certificate.user = request.user
        certificate.csr = request
        certificate.x509 = cert_utils.export_certificate(x509)
        certificate.serial = serial
        certificate.subject = cert_utils.components_to_name(subject)
        certificate.valid_from = datetime.now(pytz.utc)
        certificate.valid_to = datetime.now(
            pytz.utc) + timedelta(days=request.template.days)
        certificate.save()
        # Update the request
        request.status = Request.STATUS_ISSUED
        request.save()
        # Update the CRL locations
        for location in crl_locations:
            location.certificates.add(certificate)
            location.save()
        print('done')
