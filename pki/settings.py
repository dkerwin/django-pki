##############################################################
## PKI settings
##############################################################

import os
from django.conf import settings

PKI_APP_DIR = os.path.abspath(os.path.dirname(__file__))

# base directory for pki storage (should be writable), defaults to PKI_APP_DIR/PKI
PKI_DIR = getattr(settings, 'PKI_DIR', os.path.join(PKI_APP_DIR, 'PKI'))

# path to openssl executable
PKI_OPENSSL_BIN = getattr(settings, 'PKI_OPENSSL_BIN', '/usr/bin/openssl')

# path to generated openssl.conf
PKI_OPENSSL_CONF = getattr(settings, 'PKI_OPENSSL_CONF',
                           os.path.join(PKI_DIR, 'openssl.conf'))

# template name for openssl.conf
PKI_OPENSSL_TEMPLATE = getattr(settings, 'PKI_OPENSSL_TEMPLATE', 'pki/openssl.conf.in')

# jquery url (defaults to pki/jquery-1.3.2.min.js)
JQUERY_URL = getattr(settings, 'JQUERY_URL', 'pki/jquery-1.3.2.min.js')

# logging (TODO: syslog, handlers and formatters)
PKI_LOG = getattr(settings, 'PKI_LOG', os.path.join(PKI_DIR, 'pki.log'))
PKI_LOGLEVEL = getattr(settings, 'PKI_LOG', 'info')

# get other settings directly from settings.py:
ADMIN_MEDIA_PREFIX = getattr(settings, 'ADMIN_MEDIA_PREFIX')
