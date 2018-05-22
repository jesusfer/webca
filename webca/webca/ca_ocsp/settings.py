from webca.settings import *
from webca.ca_ocsp import settings_local

# https://www.grc.com/passwords.htm
SECRET_KEY = 'jZ;{5M0p{t#2<gv+8%6RUK$c`6-ES+zfju>{CKTr.Z.3Tg9(F}u}3\epP4h/n4='

INSTALLED_APPS.append('webca.certstore_db')

ROOT_URLCONF = 'webca.ca_ocsp.urls'
APPEND_SLASH = False

DATABASES['certstore_db'] = {
    'ENGINE': 'django.db.backends.sqlite3',
    'NAME': os.path.join(BASE_DIR, 'db_certs.sqlite3'),
}

DATABASE_ROUTERS = ['webca.certstore_db.CertStoreDBRouter']

TEMPLATES[0]['DIRS'].append(os.path.join(
    BASE_DIR, 'webca', 'ca_admin', 'templates'))

TEMPLATES[0]['OPTIONS']['libraries'] = {
    'ca_admin': 'webca.ca_admin.templatetags.ca_admin',
}

# Local settings
if hasattr(settings_local, 'DATABASES'):
    DATABASES.update(settings_local.DATABASES)

if hasattr(settings_local, 'ALLOWED_HOSTS'):
    ALLOWED_HOSTS.extend(settings_local.ALLOWED_HOSTS)
