from django.conf.urls.defaults import *

from pki.views import *
#import pki.settings

urlpatterns = patterns('',
    (r'admin/pki/(?P<model>certificate|certificateauthority)/(?P<id>[0-9]+)/delete/', admin_delete),
    (r'^pki/download/(?P<type>ca|cert)/(?P<id>\d+)/$', pki_download),
    (r'^pki/locate/(?P<type>ca|cert)/(?P<id>\d+)/$', pki_chain),
    (r'^pki/tree/(?P<id>\d+)/$', pki_tree),
    (r'^pki/email/(?P<type>ca|cert)/(?P<id>\d+)/$', pki_email),
)
