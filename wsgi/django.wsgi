import os
import sys

sys.path.append('PATH_TO_PROJECT_PARENT_FOLDER')
sys.path.append('PATH_TO_PROJECT_FOLDER')

os.environ['DJANGO_SETTINGS_MODULE'] = 'PROJECT_NAME.settings'

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()

