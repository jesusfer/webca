from django.apps import AppConfig

class CertstoreDbConfig(AppConfig):
    name = 'webca.certstore_db'
    verbose_name = 'CertStore DB'
    def ready(self):
        # We add the imports here so that Django apps have finished loading
        from webca.certstore_db.impl import DatabaseStore
        from webca.certstore import CertStore
        CertStore.register_store(DatabaseStore)
