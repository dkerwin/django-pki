=============
Configuration
=============

Create and configure Django project
===================================

If you don't have a django project yet create it now::

    $ django-admin.py startproject <YOUR_PROJECT_NAME>
    $ cd <YOUR_PROJECT_NAME>

Edit project's settings.py
==========================

1. Configure database (SQLite example)::
    
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

2. Add django-pki template directory to TEMPLATE_DIRS if 'django.template.loaders.app_directories.Loader' is not in TEMPLATE_LOADERS::
    
    TEMPLATE_LOADERS = (
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader', <== 
    )
    
    or
    
    TEMPLATE_DIRS = ('/Library/Python/2.6/site-packages/pki/templates',)

3. Add 'pki.middleware.PkiExceptionMiddleware' to MIDDLEWARE_CLASSES (used for exception logging)::
    
    MIDDLEWARE_CLASSES = (
        ...
        'pki.middleware.PkiExceptionMiddleware',
    )

4. Add 'django.contrib.admin' and 'pki' to INSTALLED_APPS::
    
    INSTALLED_APPS = (
        ...
        'django.contrib.admin',
        'pki',
        'south',
    )

5. Set MEDIA_URL and MEDIA_ROOT
    
    The values of MEDIA_URL and MEDIA_ROOT depend on your configuration.
    MEDIA_ROOT is the filesystem path to the django-pki media files (<PATH_TO_DJANGO_PKI>/media). You can of cause copy or symlink the files to another location.
    MEDIA_URL is the URL part where the media files can be accessed. Here are some examples::
        
        MEDIA_ROOT = '/Library/Python/2.6/site-packages/pki/media/'
        MEDIA_ROOT = '/var/www/myhost/static/pki'
        
        MEDIA_URL = '/static/'
        MEDIA_URL = '/pki_media/'

6. Set ADMIN_MEDIA_PREFIX

Configure django-pki settings (in projects settings.py)
=======================================================

You can use any combination of the following parameters:

* ``PKI_DIR`` - Default=/path-to-django-pki/PKI: absolute path to directory for pki storage. Must be writable
* ``PKI_OPENSSL_BIN`` - Default=/usr/bin/openssl: path to openssl binary
* ``PKI_OPENSSL_CONF`` - Default=PKI_DIR/openssl.conf: where to store openssl config
* ``PKI_OPENSSL_TEMPLATE`` - Default=pki/openssl.conf.in: openssl configuration template
* ``PKI_LOG`` - Default=PKI_DIR/pki.log: absolute path for log file
* ``PKI_LOGLEVEL`` - Default=info: logging level
* ``JQUERY_URL`` - Default=pki/jquery-1.4.2.min.js: jquery url
* ``PKI_SELF_SIGNED_SERIAL`` - Default=0x0: The serial of self-signed certificates. Set to 0 or 0x0 to get a random number (0xabc = HEX; 123 = DEC)
* ``PKI_DEFAULT_COUNTRY`` - Default=DE: The default country (as 2-letter code) selected (http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)
* ``PKI_ENABLE_GRAPHVIZ`` - Default=False: Enable graphviz support (see requirements)
* ``PKI_GRAPHVIZ_DIRECTION`` - Default=LR: Graph tree direction (LR=left-to-right, TD=top-down)
* ``PKI_ENABLE_EMAIL`` - Default=False: Email delivery to certificate's email address

Configure projects urls.py
==========================

1. Enable admin application::
    
    from django.contrib import admin 
    admin.autodiscover()

2. Add exception handler::
    
    handler500 = 'pki.views.show_exception'

3. Add the following lines to urlpatterns (make sure pki.urls is specified before admin.site.urls)::
    
    ...
    (r'^', include('pki.urls')),
    (r'^admin/', include(admin.site.urls)),

4. **!! Do not use this in production !!** If you want to serve static files with ``./manage.py runserver`` in DEBUG mode, add the following code::
    
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
    
    $ python manage.py migrate
    Running migrations for pki:
     - Migrating forwards to 0002_auto__add_field_certificateauthority_crl_distribution.
     > pki:0001_initial
     > pki:0002_auto__add_field_certificateauthority_crl_distribution
     - Loading initial data for pki.
    No fixtures found.

