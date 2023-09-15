DATABASES = {}
DATABASES['certstore_db'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'certs.db',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
}

ALLOWED_HOSTS = ['admin.webca.net']

# OCSP
OCSP_URL = 'http://ocsp.webca.net/'

