"""
A CertStore implementation that uses Djando models to store the CA certificates.
"""
default_app_config = 'webca.certstore_db.apps.CertstoreDbConfig'

# This is the name of the databas configuration for the app in Django's settings.py
DATABASE = 'certstore_db'

class CertStoreDBRouter:
    """
    A router to control all database operations on models in the
    certstore_db application.
    """
    def db_for_read(self, model, **hints):
        """
        Attempts to read certstore_db models go to DATABASE.
        """
        if model._meta.app_label == 'certstore_db':
            return DATABASE
        return None

    def db_for_write(self, model, **hints):
        """
        Attempts to write certstore_db models go to DATABASE.
        """
        if model._meta.app_label == 'certstore_db':
            return DATABASE
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the certstore_db app is involved.
        """
        if obj1._meta.app_label == 'certstore_db' or \
           obj2._meta.app_label == 'certstore_db':
           return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the certstore_db app only appears in the DATABASE
        database.
        """
        if app_label == 'certstore_db':
            return db == DATABASE
        return None
