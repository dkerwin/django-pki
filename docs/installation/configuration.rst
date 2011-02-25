=============
Configuration
=============

Create and configure Django project
===================================

If you don't have a django project yet create one now:

.. code-block:: bash
    
    $ django-admin.py startproject <YOUR_PROJECT_NAME>
    $ cd <YOUR_PROJECT_NAME>

Edit project's settings.py
==========================

1. Configure database (SQLite example):
    
  .. code-block:: python
        
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',   # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
                'NAME': '/Users/dkerwin/dev/dpki/pki.db', # Or path to database file if using sqlite3.
                'USER': '',                      # Not used with sqlite3.
                'PASSWORD': '',                  # Not used with sqlite3.
                'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
                'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
            }
        }

2. Add django-pki template directory to TEMPLATE_DIRS if 'django.template.loaders.app_directories.Loader' is not in TEMPLATE_LOADERS:
    
  .. code-block:: python
        
        TEMPLATE_LOADERS = (
            'django.template.loaders.filesystem.Loader',
            'django.template.loaders.app_directories.Loader',
        )

  **or**
  
  .. code-block:: python
        
        TEMPLATE_DIRS = ('/Library/Python/2.6/site-packages/pki/templates',)


3. Add 'pki.middleware.PkiExceptionMiddleware' to MIDDLEWARE_CLASSES (used for exception logging):
    
  .. code-block:: python
        
        MIDDLEWARE_CLASSES = (
            '...',
            'pki.middleware.PkiExceptionMiddleware',
        )

4. Add 'django.contrib.admin' and 'pki' to INSTALLED_APPS:
    
  .. code-block:: python
        
        INSTALLED_APPS = (
            '...',
            'django.contrib.admin',
            'pki',
            'south',
        )

5. Set MEDIA_URL and MEDIA_ROOT
    
  The values of MEDIA_URL and MEDIA_ROOT depend on your configuration.
  MEDIA_ROOT is the filesystem path to the django-pki media files (<PATH_TO_DJANGO_PKI>/media). You can of cause copy or symlink the files to another location.
  MEDIA_URL is the URL part where the media files can be accessed. Here are some examples:

  .. code-block:: python

    MEDIA_ROOT = '/Library/Python/2.6/site-packages/pki/media/'
    MEDIA_ROOT = '/var/www/myhost/static/pki'
    
    MEDIA_URL = '/static/'
    MEDIA_URL = '/pki_media/'

6. Set ADMIN_MEDIA_PREFIX

Configure django-pki settings (in projects settings.py)
=======================================================

You can use any combination of the following parameters:

**PKI_DIR** (*Default = /path-to-django-pki/PKI; Type = Python String*)
    Absolute path to directory for pki storage. Must be writable

**PKI_OPENSSL_BIN** (*Default = /usr/bin/openssl; Type = Python String*)
    Path to openssl binary

**PKI_OPENSSL_CONF** (*Default = PKI_DIR/openssl.conf; Type = Python String*)
    Location of OpenSSL config file (openssl.conf)

**PKI_OPENSSL_TEMPLATE** (*Default = pki/openssl.conf.in; Type = Python String*)
    OpenSSL configuration template (Shouldn't be changen unless really neccessary)

**PKI_LOG** (*Default = PKI_DIR/pki.log; Type = Python String*)
    Full qualified path to logfile for PKI actions

**PKI_LOGLEVEL** (*Default = info; Type = Python String*)
    Logging level according to Python logging module

**JQUERY_URL** (*Default = pki/jquery-1.4.2.min.js; Type = Python String*)
    Alternative jQuery url

**PKI_SELF_SIGNED_SERIAL** (*Default = 0x0; Type = Python Number*)
    The serial of self-signed certificates. Set to 0 or 0x0 to get a random number (0xabc = HEX; 123 = DEC)

**PKI_DEFAULT_COUNTRY** (*Default = DE; Type = Python String*)
    The default country (as 2-letter code) selected (http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)

**PKI_ENABLE_GRAPHVIZ** (*Default = False; Type = Python Boolean*)
    Enable graphviz support (see requirements)

**PKI_GRAPHVIZ_DIRECTION** (*Default = LR; Type = Python String*)
    Graph tree direction (LR=left-to-right, TD=top-down)

**PKI_ENABLE_EMAIL** (*Default = False; Type = Python Boolean*)
    Email delivery to certificate's email address. May require additional `Django paramters (EMAIL_*) <http://docs.djangoproject.com/en/dev/ref/settings/>`_

**Example:**
::
    
    ## django-pki specific parameters
    PKI_DIR = '/var/pki/ssl_store'
    PKI_OPENSSL_BIN = '/opt/openssl/bin/openssl'
    PKI_OPENSSL_CONF = '/opt/openssl/bin/etc/openssl.conf'
    PKI_LOG = '/var/log/django-pki.log'
    PKI_LOGLEVEL = 'error'
    JQUERY_URL = 'http://static.company.com/js/jquery.js'
    PKI_SELF_SIGNED_SERIAL = 0x0
    PKI_DEFAULT_COUNTRY = 'UK'
    PKI_ENABLE_GRAPHVIZ = True
    PKI_GRAPHVIZ_DIRECTION = 'TD'
    PKI_ENABLE_EMAIL = True
    
    ## django specific email configuration
    EMAIL_HOST = "192.168.1.1"
    EMAIL_HOST_USER = "relayuser"
    EMAIL_HOST_PASSWORD = "icanrelay"
    DEFAULT_FROM_EMAIL = "pki@my-company.com"

Configure projects urls.py
==========================

1. Enable admin application::
    
    from django.contrib import admin 
    admin.autodiscover()

2. Add exception handler::
    
    handler500 = 'pki.views.show_exception'

3. Add the following lines to urlpatterns

  ::
    
    (r'^admin/', include(admin.site.urls)),
    (r'^', include('pki.urls')),

4. If you want to serve static files with ``./manage.py runserver`` in DEBUG mode, add the following code:
    
  .. warning:: **!! Do not use this in production !!**
    
  ::

    from django.conf import settings
    
    if settings.DEBUG:
        M = settings.MEDIA_URL
        if M.startswith('/'): M = M[1:]
        if not M.endswith('/'): M += '/'
        urlpatterns += patterns('', (r'^%s(?P<path>.*)$' % M, 'django.views.static.serve',
                                {'document_root': settings.MEDIA_ROOT}))

Initialize database
===================

* Initialize database::
    
    $ python manage.py syncdb
    Syncing...
    Creating table auth_permission
    Creating table auth_group_permissions
    Creating table auth_group
    Creating table auth_user_user_permissions
    Creating table auth_user_groups
    Creating table auth_user
    Creating table auth_message
    Creating table django_content_type
    Creating table django_session
    Creating table django_site
    Creating table django_admin_log
    Creating table south_migrationhistory
    
    You just installed Django's auth system, which means you don't have any superusers defined.
    Would you like to create one now? (yes/no): yes
    Username (Leave blank to use 'dkerwin'): admin
    E-mail address: a@b.com
    Password: 
    Password (again): 
    Superuser created successfully.
    Installing index for auth.Permission model
    Installing index for auth.Group_permissions model
    Installing index for auth.User_user_permissions model
    Installing index for auth.User_groups model
    Installing index for auth.Message model
    Installing index for admin.LogEntry model
    No fixtures found.
    
    Synced:
     > django.contrib.auth
     > django.contrib.contenttypes
     > django.contrib.sessions
     > django.contrib.sites
     > django.contrib.messages
     > django.contrib.admin
     > debug_toolbar
     > south
    
    Not synced (use migrations):
     - pki
    (use ./manage.py migrate to migrate these)

* Create django-pki tables. This is a south migration::
    
    $ python manage.py migrate pki
    Running migrations for pki:
     - Migrating forwards to 0003_auto__add_pkichangelog.
     > pki:0001_initial
     > pki:0002_auto__add_field_certificateauthority_crl_distribution
     > pki:0003_auto__add_pkichangelog
     - Loading initial data for pki.
    No fixtures found.
