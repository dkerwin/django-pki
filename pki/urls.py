from django.conf.urls.defaults import *
from pki.views import *

urlpatterns = patterns('',
    url(r'admin/pki/(?P<model>certificate|certificateauthority)/(?P<id>[0-9]+)/delete/', admin_delete),
    url(r'^pki/download/(?P<model>certificate|certificateauthority)/(?P<id>\d+)/$', pki_download, name="download"),
    url(r'^pki/chain/(?P<model>certificate|certificateauthority)/(?P<id>\d+)/$', pki_chain, name="chain"),
    url(r'^pki/tree/(?P<id>\d+)/$', pki_tree, name="tree"),
    url(r'^pki/email/(?P<model>certificate|certificateauthority)/(?P<id>\d+)/$', pki_email, name="email"),
    url(r'^pki/refresh_metadata/$', pki_refresh_metadata, name="refresh_metadata"),
)
