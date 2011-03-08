##############################################################
## PKI settings
##############################################################

import os
from django.conf import settings
from django.core.urlresolvers import get_script_prefix

PKI_APP_DIR = os.path.abspath(os.path.dirname(__file__))

# base directory for pki storage (should be writable), defaults to PKI_APP_DIR/PKI
PKI_DIR = getattr(settings, 'PKI_DIR', os.path.join(PKI_APP_DIR, 'PKI'))

# path to openssl executable
PKI_OPENSSL_BIN = getattr(settings, 'PKI_OPENSSL_BIN', '/usr/bin/openssl')

# path to generated openssl.conf
PKI_OPENSSL_CONF = getattr(settings, 'PKI_OPENSSL_CONF', os.path.join(PKI_DIR, 'openssl.conf'))

# template name for openssl.conf
PKI_OPENSSL_TEMPLATE = getattr(settings, 'PKI_OPENSSL_TEMPLATE', 'pki/openssl.conf.in')

# jquery url (defaults to pki/jquery-1.3.2.min.js)
JQUERY_URL = getattr(settings, 'JQUERY_URL', 'pki/js/jquery-1.5.min.js')

# logging (TODO: syslog, handlers and formatters)
PKI_LOG = getattr(settings, 'PKI_LOG', os.path.join(PKI_DIR, 'pki.log'))
PKI_LOGLEVEL = getattr(settings, 'PKI_LOGLEVEL', 'debug')

# get other settings directly from settings.py:
ADMIN_MEDIA_PREFIX = getattr(settings, 'ADMIN_MEDIA_PREFIX')

# media url
MEDIA_URL = getattr(settings, 'MEDIA_URL')

# base url: Automatically determined
PKI_BASE_URL = getattr(settings, 'PKI_BASE_URL', get_script_prefix())

# self_signed_serial; The serial a self signed CA starts with. Set to 0 or 0x0 for a random number
PKI_SELF_SIGNED_SERIAL = getattr(settings, 'PKI_SELF_SIGNED_SERIAL', 0x0)

# default key length: The pre-selected key length
PKI_DEFAULT_KEY_LENGTH = getattr(settings, 'PKI_DEFAULT_KEY_LENGTH', 1024)

# default_country: The default country selected (2-letter country code)
PKI_DEFAULT_COUNTRY = getattr(settings, 'PKI_DEFAULT_COUNTRY', 'DE')

# passphrase_min_length: The minimum passphrase length
PKI_PASSPHRASE_MIN_LENGTH = getattr(settings, 'PKI_PASSPHRASE_MIN_LENGTH', 8)

# enable graphviz_support: When True django-pki will render Graphviz PNG's to show relations
PKI_ENABLE_GRAPHVIZ = getattr(settings, 'PKI_ENABLE_GRAPHVIZ', False)

# graphviz direction: From left to right (LR) or top down (TD)
PKI_GRAPHVIZ_DIRECTION = getattr(settings, 'PKI_GRAPHVIZ_DIRECTION', 'LR')

# enable email delivery: Certificates with defined email address can be sent via email
PKI_ENABLE_EMAIL = getattr(settings, 'PKI_ENABLE_EMAIL', False)

