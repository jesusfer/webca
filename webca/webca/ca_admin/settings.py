from webca.settings import *

# https://www.grc.com/passwords.htm
SECRET_KEY = 'jZ;{5M0p{t#2<gv+8%6RUK$c`6-ES+zfju>{CKTr.Z.3Tg9(F}u}3\epP4h/n4='

INSTALLED_APPS.append('webca.certstore_db')

ROOT_URLCONF = 'webca.ca_admin.urls'

DATABASES['certstore_db'] = {
    'ENGINE': 'django.db.backends.sqlite3',
    'NAME': os.path.join(BASE_DIR, 'db_certs.sqlite3'),
}

DATABASE_ROUTERS = ['webca.certstore_db.CertStoreDBRouter']
