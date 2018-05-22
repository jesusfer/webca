from webca.settings import *
from webca.ca_service import settings_local

# https://www.grc.com/passwords.htm
SECRET_KEY = '*F_MQCMw.,+RmYaux\J3kB7apGfrw%LI$)v$yt6@ErSw4;{2i5|0!}Ouxv*Y%T'

INSTALLED_APPS.append('webca.certstore_db')

ROOT_URLCONF = ''

DATABASES['certstore_db'] = {
    'ENGINE': 'django.db.backends.sqlite3',
    'NAME': os.path.join(BASE_DIR, 'db_certs.sqlite3'),
}

DATABASE_ROUTERS = ['webca.certstore_db.CertStoreDBRouter']

# Local settings
if hasattr(settings_local, 'DATABASES'):
    DATABASES.update(settings_local.DATABASES)

OCSP_URL = ''
if hasattr(settings_local, 'OCSP_URL'):
    OCSP_URL = settings_local.OCSP_URL
