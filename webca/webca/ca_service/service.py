"""
Implementation of the CA service.
"""
import json
import time
import traceback
from datetime import datetime, timedelta

import pytz
from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from OpenSSL import crypto

from webca import utils as ca_utils
from webca.certstore import CertStore
from webca.config import constants as parameters
from webca.config import new_crl_config
from webca.config.models import ConfigurationObject as Config
from webca.crypto import utils as cert_utils
from webca.crypto import certs, crl
from webca.crypto.constants import REV_REASON
from webca.crypto import extensions as crypto_extensions
from webca.web.models import (Certificate, CRLLocation, Request, Revoked,
                              Template)

SLEEP = 1

class ServiceError(Exception):
    pass

class CAService:
    """Polling service that processes requests from end users."""

    pending_requests = Q(status=Request.STATUS_PROCESSING) & Q(approved=True)

    # Initialization and service

    #pylint: disable=w0613
    def __init__(self, *args, **kwargs):
        # Get the current certificates
        self.refresh_certificates()

    def refresh_certificates(self):
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
        if not self.certsign[0] or not self.crlsign[0] or not self.csrsign[0]:
            raise ServiceError('The CA certificates are not correctly configured.')

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
            time.sleep(SLEEP)
            self.process_requests()
            self.process_crl()

    # Output and control

    def fatal_error(self, message):
        """Print a message and exit."""
        print(message)
        exit(-2)

    # The stuff

    def process_requests(self):
        """Process a list of requests that have been approved."""
        requests = Request.objects.filter(self.pending_requests)
        if requests:
            self.refresh_certificates()
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
        # If the template is for user certificates, then modify the subject
        if request.template.required_subject == Template.SUBJECT_USER:
            d = ca_utils.tuples_as_dict(subject)
            subject_email = d.pop('emailAddress')
            subject = ca_utils.dict_as_tuples(d)
        else:
            subject_email = None
        # If there's a SAN, add it here
        # request.san is a comma separated list
        san = []
        if request.san:
            san = request.san.split(',')
        if subject_email:
            san.append('email:%s' % subject_email)
        if san:
            ext = crypto_extensions.build_san(','.join(san))
            extensions.append(ext)
        # Now build the CDP extension.
        crl_locations = CRLLocation.get_locations()
        if crl_locations:
            ext = crypto_extensions.build_cdp(crl_locations.values_list('url', flat=True))
            extensions.append(ext)
        # Add the OCSP extension
        if settings.OCSP_URL:
            ext = crypto_extensions.json_to_extension('{"name":"authorityInfoAccess", "critical":false, "value":"OCSP;URI:%s"}' % settings.OCSP_URL)
            extensions.append(ext)
        # Validate stuff
        # Key size. Template requirements might have changed since the request was done
        key_type = cert_utils.public_key_type(request.get_csr())
        min_bits = request.template.min_bits_for(key_type)

        if pub_key.bits() < min_bits:
            # The request at this point will never meet the template minimum
            # so it should be rejected
            request.status = Request.STATUS_REJECTED
            request.reject_reason = 'The key does not meet the required '
            'minimum size: size={} required={}'.format(
                pub_key.bits(),
                min_bits)
            request.save()
            return

        # New stuff
        serial = cert_utils.new_serial()
        valid_from = 0
        valid_to = int(timedelta(days=request.template.days).total_seconds())
        # Generate CSR and then the certificate
        try:
            new_csr = certs.create_cert_request(
                pub_key,
                name=subject,
                extensions=extensions,
                signing_key=self.csrsign[1]
            )
        except crypto.Error as ex:
            print('error!')
            request.status = Request.STATUS_ERROR
            error = traceback.format_exc().replace(settings.BASE_DIR, '')
            request.admin_comment = 'Error creating internal CSR:\n%s' % error
            request.save()
            return
        try:
            x509 = certs.create_certificate(
                new_csr,
                self.certsign,
                serial,
                (valid_from, valid_to)
            )
        except crypto.Error as ex:
            print('error!')
            request.status = Request.STATUS_ERROR
            error = traceback.format_exc().replace(settings.BASE_DIR, '')
            request.admin_comment = 'Error creating certificate: %s' % error
            request.save()
            return

        # Save the new certificate
        certificate = Certificate()
        certificate.user = request.user
        certificate.csr = request
        certificate.x509 = cert_utils.export_certificate(x509)
        certificate.serial = serial
        certificate.subject = cert_utils.components_to_name(subject)
        certificate.valid_from = datetime.now(pytz.utc)
        certificate.valid_to = (datetime.now(pytz.utc) +
                                timedelta(days=request.template.days))
        certificate.save()
        # Update the request
        request.status = Request.STATUS_ISSUED
        request.save()
        # Update the CRL locations
        for location in crl_locations:
            location.certificates.add(certificate)
            location.save()
        print('done')

    def process_crl(self):
        """Check if there is a CRL to sign."""
        value = Config.get_value(
            parameters.CRL_CONFIG) or json.dumps(new_crl_config())
        try:
            crl_config = json.loads(value)
        except json.decoder.JSONDecodeError as exc:
            # This should not happen
            print('Error loading CRL config!! -> %s' % exc)
            return
        now = timezone.now()
        next = now - timedelta(days=1)
        if crl_config['last_update']:
            next = datetime.fromtimestamp(crl_config['last_update'], pytz.utc)
            next += timedelta(days=crl_config['days'])
        # TODO: handle errors, should we keep trying?
        if now > next:
            print('CRL time!')
            # Refresh signing certificates
            self.refresh_certificates()
            # Get CRL signing certificate
            crl_cert, crl_key = self.crlsign
            # Get Revoked certificates
            # TODO: should it be filtered with certs only signed by the current certificate?
            revoked_list = [
                (int(r.certificate.serial, 16), r.date, REV_REASON[r.reason])
                for r in Revoked.objects.all()
            ]
            # Build CRL
            x509crl = crl.create_crl(
                revoked_list,
                crl_config['days'],
                self.crlsign,
                crl_config['sequence'],
            )
            # Export CRL to path
            try:
                crl_file = open(crl_config['path'], 'w')
                crl_file.write(cert_utils.export_crl(x509crl))
                crl_file.close()
            except Exception as ex:
                crl_config.update({
                    'status': str(ex),
                })
                Config.set_value(parameters.CRL_CONFIG, json.dumps(crl_config))
                self.fatal_error(ex)
            # Update CRL config
            next = now + timedelta(days=crl_config['days'])
            crl_config.update({
                'last_update': now.timestamp(),
                'next_update': next.timestamp(),
                'sequence': crl_config['sequence'] + 1,
                'status': 'OK',
            })
            Config.set_value(parameters.CRL_CONFIG, json.dumps(crl_config))
            print('CRL done')
