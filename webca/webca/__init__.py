import importlib

# Check dependencies
try:
    import secrets
except ModuleNotFoundError:
    print('"secrets" not found. Are you using Python >= 3.6?')
    exit(-1)

dependencies = [
    ('django', 'pip install django'),
    ('OpenSSL', 'pip install pyopenssl'),
    ('rules', 'pip install rules'),
    ('django_ssl_auth', 'pip install django_ssl_auth'),
    ('widget_tweaks', 'pip install django-widget-tweaks'),
    ('sslserver', 'pip install django-sslserver'),
]

error = False
for module, install in dependencies:
    try:
        importlib.import_module(module)
    except ModuleNotFoundError:
        error = True
        print('Module {} not found. Please install it ({})'.format(
            module, install
        ))
    except:
        pass

if error:
    print('Exiting...')
    exit(-1)
