from django.urls import path
from django.views.generic import TemplateView

from webca.web.views import requests

app_name = 'req'
urlpatterns = [
    path('', requests.IndexView.as_view(), name='index'),
    path('view/<int:request_id>/', requests.view_certificate, name='view_cert'),
    path('new/', requests.NewView.as_view(), name='new'),
    path('submit/', requests.SubmitView.as_view(), name='submit'),
    path('ok/', requests.request_confirmation, name='ok'),
    path('examples/', TemplateView.as_view(template_name="webca/web/requests/examples.html"), name='examples'),
]
