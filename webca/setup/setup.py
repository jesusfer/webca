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
import getpass
import io
import json
import os
import re
import sys

BASE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.path.pardir))
sys.path.append(BASE_DIR)

os.environ["DJANGO_SETTINGS_MODULE"] = "webca.ca_admin.settings"

from webca.certstore import CertStore
from webca.config import constants as p
from webca.config import new_crl_config
from webca.crypto import certs
from webca.crypto import constants as c
from webca.crypto.utils import int_to_hex, new_serial
from webca.crypto.extensions import json_to_extension
from webca.utils import dict_as_tuples
from webca.utils.iso_3166 import ISO_3166_1_ALPHA2_COUNTRY_CODES as iso3166

MSG_DB = """\nA database is needed to store templates, user requests and issued certificates."""
MSG_DB_CERTS = """\nAnother database is needed to store the CA certificates.
It should a different than the web database."""


def setup():
    """Orchestrate the setup process."""
    print('\n*** Setup of database servers ***')
    config = {}
    config.update(get_database(MSG_DB, 'web_'))
    config.update(get_database(MSG_DB_CERTS, 'certs_'))
    hosts = get_host_names()
    print("""\nReview the options above, they are needed to continue.\n""")
    option = input('Continue? (Y/n)').lower()
    if option == 'n':
        sys.exit(-1)
    create_settings(config, hosts)
    init_django()
    print('\n*** Setup of CA certificates ***')
    setup_certificates()
    setup_crl_publishing()
    install_templates()
    setup_user_groups()
    setup_super_user()
    setup_email()


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
        prefix+'engine': _get_engine(engine),
        prefix+'server': server,
        prefix+'name': name,
        prefix+'user': user,
        prefix+'password': password,
        prefix+'port': port,
    }
    return config


def _get_engine(number):
    if not isinstance(number, int):
        number = int(number)
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

ALLOWED_HOSTS = """
ALLOWED_HOSTS = {}
"""

OCSP_URL = """
# OCSP
OCSP_URL = 'http://{}/'

"""


def get_host_names():
    """Get the required host names for ALLOWED_HOSTS"""
    print("""
As a security measure, the web applications need to know the host names that will be used by the users to access them.
We need to configure the host for the public web and another for the admin web.

The OCSP reponder also needs a hostname. Requests will go to http://<ocsp_host>/
""")
    web_host = input('Public web host: ').lower()
    admin_host = input('Admin web host: ').lower()
    ocsp_host = input('OCSP host:').lower()
    option = input('\nAre these correct? (Y/n)').lower()
    if option == 'n':
        return get_host_names()
    return {'web': web_host, 'admin': admin_host, 'ocsp': ocsp_host}


def create_settings(config, hosts):
    """Write settings files."""
    web_path = os.path.join(BASE_DIR, 'webca', 'settings_local.py')
    admin_path = os.path.join(
        BASE_DIR, 'webca', 'ca_admin', 'settings_local.py')
    service_path = os.path.join(
        BASE_DIR, 'webca', 'ca_service', 'settings_local.py')
    ocsp_path = os.path.join(BASE_DIR, 'webca', 'ca_ocsp', 'settings_local.py')
    _create_db_settings(config, 'web_', DB_DEFAULT, web_path)
    _create_db_settings(config, 'certs_', DB_CERTS, admin_path)
    _create_db_settings(config, 'certs_', DB_CERTS, service_path)
    _create_db_settings(config, 'certs_', DB_CERTS, ocsp_path)

    _generic_settings(web_path, ALLOWED_HOSTS.format([hosts['web']]))
    _generic_settings(admin_path, ALLOWED_HOSTS.format([hosts['admin']]))
    _generic_settings(admin_path, OCSP_URL.format(hosts['ocsp']))
    _generic_settings(service_path, OCSP_URL.format(hosts['ocsp']))
    _generic_settings(ocsp_path, ALLOWED_HOSTS.format([hosts['ocsp']]))


def _create_db_settings(config, prefix, template, path):
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


def _generic_settings(path, value):
    settings_local = open(path, 'a+', encoding='utf-8')
    settings_local.writelines(value)
    settings_local.close()


def init_django():
    """Initialize Django."""
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
        call_command('migrate', interactive=False)
    except ImproperlyConfigured as ex:
        print('Error setting up databases: {}'.format(ex))
    try:
        call_command('migrate', 'certstore_db',
                     database='certstore_db',
                     settings='webca.ca_admin.settings',
                     interactive=False)
    except ImproperlyConfigured as ex:
        print('Error setting up databases: {}'.format(ex))


def setup_certificates():
    """Setup the CA certificates."""
    print('\nA CA certificate needs to be imported or created.')
    # List available certificate stores
    stores = CertStore.all()
    print('These are the available certificate stores.')
    if len(stores) == 1:
        name, cls = stores[0]
        print('The only store available is: %s' % name)
        store = cls()
    else:
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
    ca_key, ca_cert = _setup_certificates_ca(store)
    _setup_certificates_csr(store)
    # FUTURE: this doesn't make sense anymore. we are not using client cert auth now
    _setup_certificates_user(store, ca_key, ca_cert)
    _setup_certificates_ocsp(store, ca_key, ca_cert)


def _setup_certificates_csr(store):
    """Create CSR signing keypair/certificate"""
    from webca.config.models import ConfigurationObject as Config
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


def _setup_certificates_ca(store):
    """Set up the CA certificate."""
    from webca.config.models import ConfigurationObject as Config
    print('\nThe CA needs a certificate. '
          'You must import one or create a self-signed one now.')
    option = 0
    while option not in [1, 2]:
        print('\n1. Import a PFX')
        print('2. Generate a self-signed Root CA using RSA')
        option = input('Choose an option: ')
        try:
            option = int(option)
        except ValueError:
            pass

    ca_key = ca_cert = ca_serial = None

    if option == 1:
        # Import a PFX
        filename = input('Filename: ')
        from django.core.management import call_command, CommandError
        try:
            out = io.StringIO()
            call_command('importpfx', filename,
                         store.__class__.__name__, stdout=out)
            ca_serial = re.search(r'serial=(\w+)', out.getvalue()).groups()[0]
            ca_cert = store.get_certificate(ca_serial)
            ca_key = store.get_private_key(ca_serial)
        except CommandError as ex:
            print('Error importing PFX: %s' % ex)
            sys.exit()
    else:
        # Generate a self-signed CA
        bits = -1
        while bits < 2048:
            try:
                bits = input('Key size (min 2048 bits): ')
                if not bits:
                    bits = 2048
                else:
                    bits = int(bits)
            except ValueError:
                pass
        c = -1
        while c == -1:
            c = input('Country (2-letters): ').upper()
            if c and c not in iso3166:
                c = -1
        st = input('State: ')
        l = input('Locality: ')
        o = input('Organization: ')
        ou = input('Organizational Unit: ')
        cn = input('Common name: ')

        print('\nThis is the name of the certificate:')
        print("""
        Country: %s
        State: %s
        Locality: %s
        Organization: %s
        Organizational Unit: %s
        Common Name: %s""" % (c, st, l, o, ou, cn))

        option = input('Is this OK? (Y/n)').lower()
        if option == 'n':
            return _setup_certificates_ca(store)
        else:
            name = {}
            if c:
                name['C'] = c
            if st:
                name['ST'] = st
            if l:
                name['L'] = l
            if o:
                name['O'] = o
            if ou:
                name['OU'] = ou
            if cn:
                name['CN'] = cn
            name = dict_as_tuples(name)
            ca_key, ca_cert = certs.create_ca_certificate(name, bits)
            store.add_certificate(ca_key, ca_cert)
            ca_serial = int_to_hex(ca_cert.get_serial_number())
    Config.set_value(p.CERT_KEYSIGN, '{},{}'.format(
        store.STORE_ID, ca_serial
    ))
    Config.set_value(p.CERT_CRLSIGN, '{},{}'.format(
        store.STORE_ID, ca_serial
    ))
    return ca_key, ca_cert


def _setup_certificates_user(store, ca_key, ca_cert):
    """Create user authentication certificate."""
    from webca.config.models import ConfigurationObject as Config
    name = [
        ('CN', 'User Authencation'),
        ('O', 'WebCA'),
    ]
    user_key, user_cert = certs.create_ca_certificate(
        name, 2048, pathlen=0, duration=10*365*24*3600,
        signing_cert=(ca_cert, ca_key))
    store.add_certificate(user_key, user_cert)
    Config.set_value(p.CERT_USERSIGN, '{},{}'.format(
        store.STORE_ID, int_to_hex(user_cert.get_serial_number())
    ))


def _setup_certificates_ocsp(store, ca_key, ca_cert):
    """Create OCSP signing certificate."""
    from webca.config.models import ConfigurationObject as Config
    name = [
        ('CN', 'OCSP Signing'),
        ('O', 'WebCA'),
    ]
    ocsp_key = certs.create_key_pair(c.KEY_RSA, 2048)
    extensions = [
        json_to_extension(
            '{"name":"keyUsage","critical":true,"value":"digitalSignature"}'),
        json_to_extension(
            '{"name":"extendedKeyUsage","critical":false,"value":"OCSPSigning"}'),
    ]
    ocsp_csr = certs.create_cert_request(ocsp_key, name, extensions)
    ocsp_cert = certs.create_certificate(
        ocsp_csr, (ca_cert, ca_key), new_serial(), (0, 10*365*24*3600))
    store.add_certificate(ocsp_key, ocsp_cert)
    Config.set_value(p.CERT_OCSPSIGN, '{},{}'.format(
        store.STORE_ID, int_to_hex(ocsp_cert.get_serial_number())
    ))


def setup_crl_publishing():
    """Do some minimal CRL configuration.
    We just need to create the default configuration.

    The CRLs will be published every 15 days and the location will be the STATIC folder.
    """
    from django.conf import settings
    from webca.config.models import ConfigurationObject as Config
    from webca.web.models import CRLLocation
    print("\n\nCRL publishing setup.\n\nA URL where the CRL will be published is needed.")
    crl_url = input("CRL location: ")
    # TODO: Validate the URL
    crl = CRLLocation(url=crl_url)
    crl.save()

    config = new_crl_config()
    config['path'] = settings.STATIC_ROOT
    Config.set_value(p.CRL_CONFIG, json.dumps(config))
    print("Default CRL publishing freq: 15 days")
    print("Default CRL publishing path: %s" % config['path'])


def install_templates():
    print('\nDo you want some certificate templates to be automatically created?')
    option = input('Continue? (Y/n): ').lower()
    if option == 'n':
        return
    from django.core import serializers
    data = open(os.path.join(BASE_DIR, 'setup/templates.json'))
    templates = serializers.deserialize('json', data)
    for template in templates:
        template.save()
        print('Created: %s' % template.object.name)


def setup_user_groups():
    """Create the default groups"""
    from django.contrib.auth.models import Group
    group = Group(name="All Users")
    group.save()
    group = Group(name="Operators")
    group.save()


def setup_super_user():
    from django.core.management import call_command
    from django.core.exceptions import ImproperlyConfigured
    print("A super user/administrator needs to be created.")
    try:
        call_command("createsuperuser", interactive=True)
    except ImproperlyConfigured as ex:
        print('Error setting up databases: {}'.format(ex))


def setup_email():
    from django.conf import settings
    print("\nAn email server must be setup so that users can authenticate.")
    print("Review the EMAIL settings in the settings file and update them: {}".format(
        os.path.join(settings.BASE_DIR, 'webca', 'settings.py')
    ))


if __name__ == '__main__':
    try:
        setup()
    except KeyboardInterrupt:
        print('\n\n**** Setup is NOT complete ****', file=sys.stderr)
        print('**** Please run this script again ****\n', file=sys.stderr)
        sys.exit(-1)
