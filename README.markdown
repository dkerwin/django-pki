django-pki
==========

This project aims to simplify the installation and management of your personal CA infrastructure.

django-pki offers the following features:

  * CA management

    - Create CA chains based on self-signed Root CA's
    - CA's can contain other CA's or normal certificates
    - Revoke and renew for non self-signed CA's
    - Create and export PEM and DER encoded certificates
    - Automatic CRL generation/update when CA or related certificate is modified

  * Certificate management

    - Revoke and renew
    - Create and export PEM, PKCS12 and DER encoded versions

django-pki stores the data in your favourite database backend (if supported by Django - MySQL, PostgreSQL, SQLite, Oracle). The main work is done by using Django's swiss army knife - the builtin admin. There is only a small number of custom views (download and logviewer).

Dependencies
------------

  * Python (tested on 2.5 and 2.6)
  * Django framework (>1.1.1 is recommended)
  * Openssl
  * Optional Jquery library (djago-pki already shipped with built-in jquery-1.3.2)

Support
-------

  * Bugs and feature requests : [http://code.google.com/p/django-pki/issues/](http://code.google.com/p/django-pki/issues/)
  * Discussion : [http://groups.google.com/group/django-pki](http://groups.google.com/group/django-pki) or django-pki@googlegroups.com

Installation
------------

1. Get the latest release or checkout from the master branch
2. Copy pki directory to your existing django project (or create new one with `django-admin.py startproject`). 
   Alternatively, you can place it somewhere in python path
3. Configure django-pki

Configuration
-------------

Make the contents of pki/media/pki directory available at `MEDIA_URL/pki` url. This can be done by making a symlink, 
copying it to your existing directory for static content, or via webserver configuration.

### Configure urls.py

Enable admin application:

    from django.contrib import admin 
    admin.autodiscover()

Add exception handler:

    handler500 = 'pki.views.show_exception'

Add following lines to urlpatterns (make sure `pki.urls` is specified before `admin.site.urls`):

    (r'^', include('pki.urls')),
    (r'^admin/', include(admin.site.urls)),

If you want to serve static files with `./manage.py runserver` in DEBUG mode, add following code. Do not use this in production!

    from django.conf import settings
    
    if settings.DEBUG:
        M = settings.MEDIA_URL
        if M.startswith('/'): M = M[1:]
        if not M.endswith('/'): M += '/'
        urlpatterns += patterns('', (r'^%s(?P<path>.*)$' % M, 'django.views.static.serve',
                                {'document_root': settings.MEDIA_ROOT}))

### Configure your project's settings.py

Enable admin application (refer to the Django documentation for additional details):

  * Add `django.contrib.admin` to `INSTALLED_APPS`
  * Configure `ADMIN_MEDIA_PREFIX` and your webserver to serve admin static files

Setup your database:

  * If you started a new project supply the database informations (refer to Django documentation for additional details)

Mandatory settings:

 * Add pki/templates to `TEMPLATE_DIRS` variable (use absolute path). Alternatively, use app_directories 
   django template loader (refer to the Django docs for details)
 * Add pki to `INSTALLED_APPS`
 * make sure `django.core.context_processors.media` is included in `TEMPLATE_CONTEXT_PROCESSORS`
   (it is enabled by default in recent Django versions)

### Configure pki/settings.py:

 * `PKI_DIR` - absolute path to directory for pki storage (defaults to /path-to-django-pki/PKI),
   should be writable
 * `PKI_OPENSSL_BIN` - path to openssl binary (/usr/bin/openssl)
 * `PKI_OPENSSL_CONF` - where to store openssl config (defaults to PKI_DIR/openssl.conf)
 * `PKI_OPENSSL_TEMPLATE` - openssl configuration template (defaults to pki/openssl.conf.in)
 * `PKI_LOG` - absolute path for log file (defaults to PKI_DIR/pki.log)
 * `PKI_LOGLEVEL` - logging level (info)
 * `JQUERY_URL` - jquery url (defaults to pki/jquery-1.3.2.min.js)
 * `PKI_BASE_URL` - Base URL of your deployment (http://xyz.com/django/tools/ => /django/tools)
 * `PKI_SELF_SIGNED_SERIAL` - The serial of self-signed CA certificates. Set to 0 or 0x0 to get a random serial number (0xabc = HEX; 123 = DEC)
 * `PKI_DEFAULT_COUNTRY` - The default country (as 2-letter code) selected when adding certificates (http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)

Additionally, you can add your own logging destinations. This is an example for syslog:

    import logging
    from logging import handlers
    
    if not hasattr(logging, 'PKI_LOGGING_INITIALIZED'):
        logging.PKI_LOGGING_INITIALIZED = True
        hdlr = handlers.SysLogHandler('/dev/log', handlers.SysLogHandler.LOG_LOCAL0)
        hdlr.setFormatter(logging.Formatter('%(name)s[%(process)d]: %(levelname)s %(funcName)s/%(lineno)d %(message)s'))
        logging.getLogger('pki').addHandler(hdlr)

Hasattr hack is required because Django imports settings.py multiple times. If you do not like
this, place handler initialization code to urls.py or somewhere else in your project.

### Do not forget to run `python manage.py syncdb` to create necessary database objects

WSGI setup example
------------------

You can find a example wsgi script in `apache/django.wsgi`.

