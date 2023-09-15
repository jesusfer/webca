"""
Command to import a PFX file into a certificate store.
"""
import argparse
import getpass

from django.core.management.base import BaseCommand, CommandError
from OpenSSL import crypto

#pylint: disable=E0611, E0401
from webca.certstore import CertificateExistsError, CertStore
from webca.crypto.utils import int_to_hex
#pylint: enable=E0611, E0401


class Command(BaseCommand):
    """This command imports a PFX into a certificate store. Handles PFX with passphrases too."""
    help = 'Import a PFX into a certificate store to be used in the CA. Handles passphrases too.'
    requires_migrations_checks = True

    def add_arguments(self, parser):
        parser.add_argument("file", type=argparse.FileType('rb', 0))
        parser.add_argument("store")

    def handle(self, *args, **options):
        # Validate store
        store = CertStore.get_by_name(options['store'])
        if not store:
            print('Store (%s) not found.' % options['store'])
            print('Available stores:')
            for name, _ in CertStore.all():
                print('> ' + name)
            raise CommandError('Choose an available store')

        # Validate PFX
        pfx = None
        pfx_file = options['file']
        pfx_raw = pfx_file.read()
        try:
            pfx = crypto.load_pkcs12(pfx_raw)
        except crypto.Error as ex:
            if 'asn1 encoding routines' in str(ex):
                raise CommandError('Not a PFX file')
            elif 'mac verify failure' in str(ex):
                print('This PFX has a passphrase.')
        except Exception as ex:
            raise CommandError('Error loading PFX file: %s' % ex)

        if not pfx:
            passphrase = getpass.getpass('Passphrase?')
            try:
                pfx = crypto.load_pkcs12(pfx_raw, passphrase)
            except crypto.Error as ex:
                if 'mac verify failure' in str(ex):
                    raise CommandError('Passphrase is not correct')
                else:
                    raise CommandError('Crypto error: %s' % str(ex))
        try:
            store.add_certificate(
                pfx.get_privatekey(),
                pfx.get_certificate(),
            )
        except CertificateExistsError:
            raise CommandError('Error: the certificate already exists in this store.')

        self.stdout.write('Successfully imported "%s" serial=%s' % (
            pfx_file.name,
            int_to_hex(pfx.get_certificate().get_serial_number())
        ))
