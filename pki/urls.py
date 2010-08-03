from pki.views import *
from django.conf.urls.defaults import *
import pki.settings


urlpatterns = patterns('',
    (r'admin/pki/(?P<model>certificate|certificateauthority)/(?P<id>[0-9]+)/delete/', admin_delete),
    (r'^pki/ca-download/(?P<ca>[a-zA-Z0-9\-_]+)/(?P<type>chain|crl|pem|der)/$', ca_download),
    (r'^pki/cert-download/(?P<cert>[a-zA-Z0-9\-_\.]+)/(?P<type>chain|crl|pem|der|pkcs12)/$', cert_download),
)
