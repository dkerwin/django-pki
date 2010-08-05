from pki.views import *
from django.conf.urls.defaults import *
import pki.settings


urlpatterns = patterns('',
    (r'admin/pki/(?P<model>certificate|certificateauthority)/(?P<id>[0-9]+)/delete/', admin_delete),
    (r'^pki/download/(?P<type>ca|cert)/(?P<id>\d+)/(?P<item>chain|crl|pem|der|pkcs12|key|csr)/$', pki_download),
)
