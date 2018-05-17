"""
Command to import a PFX file into a certificate store.

--list: list store names

--file pfx --store StoreName
"""
import argparse
import getpass
from django.core.management.base import BaseCommand, CommandError
from OpenSSL import crypto
from webca.certstore import CertStore, CertificateExistsError


class Command(BaseCommand):
    help = 'Import a PFX into a certificate store to be used in the CA'
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
            return

        # Validate PFX
        pfx = None
        pfx_file = options['file']
        pfx_raw = pfx_file.read()
        try:
            pfx = crypto.load_pkcs12(pfx_raw)
        except crypto.Error as ex:
            if 'asn1 encoding routines' in str(ex):
                print('Not a PFX file')
                return
            elif 'mac verify failure' in str(ex):
                print('This PFX has a passphrase.')
        except Exception as ex:
            print('Error loading PFX file: %s' % ex)

        if not pfx:
            passphrase = getpass.getpass('Passphrase?')
            try:
                pfx = crypto.load_pkcs12(pfx_raw, passphrase)
            except crypto.Error as ex:
                if 'mac verify failure' in str(ex):
                    print('Passphrase is not correct')
                else:
                    print('Crypto error: %s' % str(ex))
                return
        try:
            store.add_certificate(
                pfx.get_privatekey(),
                pfx.get_certificate(),
            )
        except CertificateExistsError:
            print('Error: the certificate already exists in this store.')
            return

        self.stdout.write('Successfully imported "%s"' % pfx_file.name)
