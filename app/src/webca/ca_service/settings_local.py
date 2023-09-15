DATABASES = {}
DATABASES['certstore_db'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'certs.db',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
}

# OCSP
OCSP_URL = 'http://ocsp.webca.net/'

