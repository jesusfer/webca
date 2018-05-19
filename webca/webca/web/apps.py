from django.apps import AppConfig


class WebConfig(AppConfig):
    name = 'webca.web'
    verbose_name = 'Public web'

    def ready(self):
        import webca.web.signals
