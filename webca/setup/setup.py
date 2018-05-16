"""
Setup script for WebCA.

The setup steps are:
1. Get DB details for the web database
2. Get DB details for the certstore database
(. Create default certificate templates)
from django.core import serializers
from webca.web.models import Template
data = serializers.serialize('json', Template.objects.all())

for deserialized_object in serializers.deserialize("json", data):
    if object_should_be_saved(deserialized_object):
        deserialized_object.save()

. Import a CA certificate
(. Generate a CA certificate for user authentication)
. Generate a local admin (Django auth)
. Generate an operator (SSL Auth?)

Inputs:
- DB details for web
- DB details for certstore
- PFX or .key/.pem with CA certificates
- Default CA certificate

Outputs:
- User certificates CA certificate

"""
# pylint: disable=E0611,E0401,C0413,W0611
import os
import getpass
import sys

BASE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.path.pardir))
sys.path.append(BASE_DIR)

os.environ["DJANGO_SETTINGS_MODULE"] = "webca.ca_admin.settings"

from webca.certstore import CertStore
from webca.config import constants as p
from webca.crypto import certs
from webca.crypto import constants as c
from webca.crypto.utils import int_to_hex

MSG_DB = """\nA database is needed to store templates, user requests and issued certificates."""
MSG_DB_CERTS = """\nAnother database is needed to store the CA certificates.
It should a different than the web database."""


def setup():
    print('\n*** Setup of database servers ***')
    config = {}
    config.update(get_database(MSG_DB, 'web_'))
    config.update(get_database(MSG_DB_CERTS, 'certs_'))
    if input('Modify settings?'):
        create_settings(config)
    init_django()
    print('\n*** Setup of CA certificates ***')
    setup_certificates()
    # TODO: setup_crl_publishing() Ask for path to publish and frequency
    install_templates()


"""
FUTURE: Just in case we wanted to filter the options
with the installed modules:
django.db.backends.sqlite3
django.db.backends.postgresql: psycopg2
django.db.backends.mysql: mysqlclient
django.db.backends.oracle: cx_Oracle
"""


def get_database(reason, prefix):
    """Get database settings."""
    print(reason)
    print("""
    Choose an engine:
    1. SQLite3
    2. PostgreSQL
    3. MySQL
    4. Oracle
    """)
    engine = input('Engine: ')
    server = input('DB Server: ')
    name = input('DB Name: ')
    user = input('User: ')
    password = getpass.getpass()
    print('To use the default port, leave blank.')
    port = input('Port: ')

    config = {
        prefix+'engine': engine,
        prefix+'server': server,
        prefix+'name': name,
        prefix+'user': user,
        prefix+'password': password,
        prefix+'port': port,
    }
    return config


def _get_engine(number):
    if number == 1:
        return 'django.db.backends.sqlite3'
    elif number == 2:
        return 'django.db.backends.postgresql'
    elif number == 3:
        return 'django.db.backends.mysql'
    elif number == 4:
        return 'django.db.backends.oracle'


DB_DEFAULT = """DATABASES = {
    'default': {
        'ENGINE': '%(engine)s',
        'NAME': '%(name)s',
        'USER': '%(user)s',
        'PASSWORD': '%(password)s',
        'HOST': '%(server)s',
        'PORT': '%(port)s',
    }
}
"""

DB_CERTS = """DATABASES = {}
DATABASES['certstore_db'] = {
        'ENGINE': '%(engine)s',
        'NAME': '%(name)s',
        'USER': '%(user)s',
        'PASSWORD': '%(password)s',
        'HOST': '%(server)s',
        'PORT': '%(port)s',
}
"""


def create_settings(config):
    """Write settings files."""
    web_path = os.path.join(BASE_DIR, 'webca', 'settings_local.py')
    admin_path = os.path.join(
        BASE_DIR, 'webca', 'ca_admin', 'settings_local.py')
    service_path = os.path.join(
        BASE_DIR, 'webca', 'ca_service', 'settings_local.py')
    _create_settings(config, 'web_', DB_DEFAULT, web_path)
    _create_settings(config, 'certs_', DB_CERTS, admin_path)
    _create_settings(config, 'certs_', DB_CERTS, service_path)


def _create_settings(config, prefix, template, path):
    print('Writing ' + path)
    settings_local = open(path, 'w', encoding='utf-8')
    settings_local.writelines(template % {
        'engine': config[prefix+'engine'],
        'server': config[prefix+'server'],
        'name': config[prefix+'name'],
        'user': config[prefix+'user'],
        'password': config[prefix+'password'],
        'port': config[prefix+'port'],
    })
    settings_local.close()


def init_django():
    print('\nInitializing Django...')
    import django
    try:
        django.setup()
    except Exception as ex:
        import traceback
        traceback.print_exc()
        print('There was an error initializing up Django: {}'.format(ex))
        print('Exiting...')
        exit()
    # Django is available, migrate first
    from django.core.management import call_command
    from django.core.exceptions import ImproperlyConfigured
    try:
        call_command("migrate", interactive=False)
    except ImproperlyConfigured as ex:
        print('Error setting up databases: {}'.format(ex))


def setup_certificates():
    print('\nA CA certificate needs to be imported or created.')
    from webca.config.models import ConfigurationObject as Config
    # List available certificate stores
    stores = CertStore.all()
    print('These are the available certificate stores.')
    option = 0
    i = 1
    while option < 1 or option > len(stores):
        for name, cls in stores:
            print('{}. {}'.format(i, name))
        option = input('Choose a certificate store: ')
        try:
            option = int(option)
        except:
            option = 0
    store = stores[option - 1][1]()
    # Create CSR signing keypair/certificate
    name = [
        ('CN', 'Internal CSR Signing'),
        ('O', 'WebCA'),
    ]
    dur = (1 << 31) - 1
    csr_keys, csr_cert = certs.create_self_signed(name, duration=dur)
    store.add_certificate(csr_keys, csr_cert)
    Config.set_value(p.CERT_CSRSIGN, '{},{}'.format(
        store.STORE_ID, int_to_hex(csr_cert.get_serial_number())
    ))
    # TODO: import CA certificate
    print('\nThe CA needs a certificate. '
          'You must import one or create a self-signed one now.')
    option = 0
    while option not in [1, 2]:
        print('\n1. Import a PFX')
        print('2. Generate a self-signed Root CA')
        option = input('Choose an option: ')
        try:
            option = int(option)
        except:
            pass
    if option == 1:
        # import_pfx(store) TODO:
        pass
    else:
        # generate a self-signed CA TODO:
        # request bits
        # request DN
        # confirm DN
        pass
    # TODO: create user authentication certificate


def install_templates():
    print('\nDo you want some certificate templates to be automatically created?')
    option = input('Omit this step (y/N): ')
    if option == 'y':
        return
    from django.core import serializers
    data = open(os.path.join(BASE_DIR, 'setup/templates.json'))
    templates = serializers.deserialize('json', data)
    for template in templates:
        print(template.object.name)
        template.save()


if __name__ == '__main__':
    try:
        setup()
    except KeyboardInterrupt:
        sys.exit(-1)
