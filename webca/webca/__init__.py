# Check dependencies
try:
    import django
except:
    print('Django missing. Use "pip install django"')
    exit(-1)

try:
    import OpenSSL
except:
    print('PyOpenssl missing. Use "pip install pyopenssl"')
    exit(-1)

try:
    import secrets
except:
    print("'secrets' library not found. Are you using Python >= 3.6?")
    exit(-1)


# TODO: We could probably do this somewhere else
from django.contrib import admin
admin.site.site_header = 'WebCA'
admin.site.index_title = 'WebCA administration'
