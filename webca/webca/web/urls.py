from django.urls import path

from webca.web.views import *

app_name = 'req'
urlpatterns = [
    path('', RequestView.as_view(), name='request_index'),
    path('new/', RequestNewView.as_view(), name='request_new'),
]
