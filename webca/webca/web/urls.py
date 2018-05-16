"""
URLconf for the public web.

"""
#pylint: disable=C0103

from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path

from webca.web.views import IndexView, requests, revocation

request_patterns = ([
    path('', requests.IndexView.as_view(), name='index'),

    path('view/<int:request_id>/', requests.view_certificate, name='view_cert'),
    path('download/<int:request_id>/pem/',
         requests.download_certificate, name='download_pem'),
    path('download/<int:request_id>/crt/',
         requests.download_certificate, {'pem': False}, name='download_crt'),

    path('new/', requests.NewView.as_view(), name='new'),
    path('submit/', requests.SubmitView.as_view(), name='submit'),
    path('ok/', requests.request_confirmation, name='ok'),

    path('examples/', requests.view_examples, name='examples'),
], 'req')

revoke_patterns = ([
    path('', revocation.IndexView.as_view(), name='index'),
    path('<int:certificate_id>/',
         revocation.RevocationView.as_view(), name='revoke'),
    path('<int:certificate_id>/update/',
         revocation.RevocationView.as_view(), name='revoke_update'),
], 'revoke')

app_patterns = ([
    path('', IndexView.as_view(), name='index'),
], 'webca')

urlpatterns = [
    path('', include(app_patterns)),
    path('request/', include(request_patterns)),
    path('revoke/', include(revoke_patterns)),
    # FIXME: STATIC only for dev
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
