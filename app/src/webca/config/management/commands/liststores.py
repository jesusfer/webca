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
    help = 'List available certificate stores'
    requires_migrations_checks = True

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        # Validate store
        print('Available stores:')
        for name, _ in CertStore.all():
            print('> ' + name)
