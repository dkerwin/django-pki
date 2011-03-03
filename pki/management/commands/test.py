from pki import settings

## Patch PKI_DIR to prevent removal of production data
try:
    PKI_DIR = getattr(settings, 'PKI_DIR')
except AttributeError, e:
    print "\n\nPKI_DIR not set!\n\n"
    raise(e)

setattr(settings, 'PKI_DIR', PKI_DIR + '____TEST_RUN____')

from south.management.commands.test import *
