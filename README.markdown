django-pki
==========

This project aims to simplify the installation and management of your personal CA infrastructure.

django-pki offers the following features:

  * CA management

    - Create CA chains based on self-signed Root CA's
    - CA's can contain other CA's or non-CA certificates
    - Revoke and renew (re-sign CSR) for all CA's
    - Create and export PEM and DER encoded certificates
    - Automatic CRL generation/update when CA or related certificate is modified

  * Certificate management

    - Revoke and renew
    - Create and export PEM, PKCS12 and DER encoded versions

django-pki stores the data in your favourite database backend (if supported by Django - MySQL, PostgreSQL, SQLite, Oracle). The main work is done by using Django's swiss army knife - the builtin admin. There is only a small number of custom views (download and logviewer).

Dependencies
------------

  * Python (tested on 2.5 and 2.6)
  * Django framework (>=1.2 is recommended)
  * Openssl
  * Optional Jquery library (djago-pki already shipped with built-in jquery-1.3.2)
  * pygraphviz + Graphviz (Tree viewer and object locator will not work without)
  * zipfile Python library

Support
-------

  * Bugs and feature requests : [http://github.com/dkerwin/django-pki/issues](http://github.com/dkerwin/django-pki/issues)
  * Discussion : [http://groups.google.com/group/django-pki](http://groups.google.com/group/django-pki) or django-pki@googlegroups.com

Installation
------------

### pip or easy_install
 
    # pip install django-pki
    or
    # easy_install django-pki
  
### Clone github repository (every release version is tagged)

    # git clone git://github.com/dkerwin/django-pki.git

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

Setup your database:

  * If you started a new project supply the database credentials (refer to Django documentation for additional details)

Mandatory settings:

 * Add pki/templates to `TEMPLATE_DIRS` variable (use absolute path). Alternatively, use app_directories 
   django template loader (refer to the Django docs for details)
 * Add pki to `INSTALLED_APPS`
 * make sure `django.core.context_processors.media` is included in `TEMPLATE_CONTEXT_PROCESSORS`
   (it is enabled by default in recent Django versions)
 * Add `pki.middleware.PkiExceptionMiddleware` to `MIDDLEWARE_CLASSES` (used for exception logging)

Enable admin application (refer to the Django documentation for additional details):

  * Add `django.contrib.admin` to `INSTALLED_APPS` (it is better to place it after django-pki to
    ensure that admin templates are properly overridden)
  * Configure `ADMIN_MEDIA_PREFIX` and your webserver to serve admin static files

#### Configure django-pki:

Add the following variables to your projects settings.py to set custom values:

 * `PKI_DIR` - Default=/path-to-django-pki/PKI: absolute path to directory for pki storage. Must be writable
 * `PKI_OPENSSL_BIN` - Default=/usr/bin/openssl: path to openssl binary
 * `PKI_OPENSSL_CONF` - Default=PKI_DIR/openssl.conf: where to store openssl config
 * `PKI_OPENSSL_TEMPLATE` - Default=pki/openssl.conf.in: openssl configuration template
 * `PKI_LOG` - Default=PKI_DIR/pki.log: absolute path for log file
 * `PKI_LOGLEVEL` - Default=info: logging level
 * `JQUERY_URL` - Default=pki/jquery-1.3.2.min.js: jquery url
 * `PKI_BASE_URL` - Default="": Base URL of your deployment (http://xyz.com/django/tools/ => /django/tools)
 * `PKI_SELF_SIGNED_SERIAL` - Default=0x0: The serial of self-signed CA certificates. Set to 0 or 0x0 to get a random serial number (0xabc = HEX; 123 = DEC)
 * `PKI_DEFAULT_COUNTRY` - Default=DE: The preselected country (as 2-letter code) selected when adding certificates (http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)
 * `PKI_ENABLE_GRAPHVIZ` - Default=False: Enable graphviz support (see requirements)
 * `PKI_GRAPHVIZ_DIRECTION` - Default=LR: Graph tree direction (LR=left-to-right, TD=top-down)
 * `PKI_ENABLE_EMAIL` - Default=False: Email delivery to certificate's email address

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

Graphviz support
----------------

django-pki can visualize your PKI infrastructure if you have pygraphviz and graphviz installed. Just install pygraphviz and enable the `PKI_ENABLE_GRAPHVIZ`
setting. The change list views for certificate authorities now has 2 clickable icons:

  * Magnifying glass: Show CA chain up to selected element
  * Tree: Show the full tree (including all certificates) in which this CA is located

The certificate change list has only the magnifying glass available. Both links open a new window and return a PNG image containing the trees. These images (especially 
the tree view) can become really big. You can affect the direction of the graph be setting PKI_GRAPHVIZ_DIRECTION to TD (top down) or LR (left right) depending on what fits
your needs best.

Email support
-------------

djngo-pki supports certificate delivery via email. All certificates that contain a valid email address can be sent to that address from the changelist screen.
Please add `PKI_ENABLE_EMAIL` and the required parameters for your email setup to your projects settings.py.

May be a combination of `EMAIL_HOST`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_PORT`, `EMAIL_SUBJECT_PREFIX`, `EMAIL_USE_TLS` and `DEFAULT_FROM_EMAIL`.
Refer to [Django settings reference](http://docs.djangoproject.com/en/1.2/ref/settings/) for details.

Icons used in django-pki
------------------------

Some Icons are Copyright (c) [Yusuke Kamiyamane](http://p.yusukekamiyamane.com/). All rights reserved.
Licensed under a [Creative Commons Attribution 3.0 license](http://creativecommons.org/licenses/by/3.0/)
