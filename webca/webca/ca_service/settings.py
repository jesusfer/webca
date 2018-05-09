from webca.settings import *

# https://www.grc.com/passwords.htm
SECRET_KEY = '*F_MQCMw.,+RmYaux\J3kB7apGfrw%LI$)v$yt6@ErSw4;{2i5|0!}Ouxv*Y%T'

INSTALLED_APPS.append('webca.certstore_db')

ROOT_URLCONF = ''

DATABASES['certstore_db'] = {
    'ENGINE': 'django.db.backends.sqlite3',
    'NAME': os.path.join(BASE_DIR, 'db_certs.sqlite3'),
}

DATABASE_ROUTERS = ['webca.certstore_db.CertStoreDBRouter']

from webca.ca_service import settings_local
DATABASES.update(settings_local.DATABASES)
