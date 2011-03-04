====================
Upgrade instructions
====================

I you already used django-pki before version 0.20.0 you have to need to do some steps after updating your installation.

.. warning:: **!! Backup your database and PKI directory BEFORE you start the upgrade !!**

Database migration
==================

* Install `south <http://south.aeracode.org/>`_  and add it to INSTALLED_APPS in settings.py
    .. warning:: Make sure **pki** is specified after **south** as unit tests won't work otherwise
    ::
        
        INSTALLED_APPS = (
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.sites',
            'django.contrib.admin',
            'south',
            'pki',
        )

* Run the initial migration as fake::
    
    $ python manage.py migrate pki 0001 --fake
    - Soft matched migration 0001 to 0001_initial.
    Running migrations for pki:
     - Migrating forwards to 0001_initial.
     > pki:0001_initial
       (faked)

* Run the other migrations::
    
    $ python manage.py migrate pki
    Running migrations for pki:
     - Migrating forwards to 0012_auto__add_unique_keyusage_name__add_unique_extendedkeyusage_name.
     > pki:0002_auto__add_field_certificateauthority_crl_distribution
     > pki:0003_auto__add_pkichangelog
     > pki:0004_auto__add_keyusage__add_x509extension__add_extendedkeyusage__del_field
     > pki:0005_load_eku_and_ku_fixture
    Installing json fixture 'eku_and_ku' from '/Library/Python/2.6/site-packages/pki/fixtures'.
    Installed 25 object(s) from 1 fixture(s)
     > pki:0006_update_objects_to_x509_extensions
     > pki:0007_auto__del_field_certificateauthority_subcas_allowed
     > pki:0008_auto__del_field_certificate_cert_extension
     > pki:0009_auto__del_field_certificateauthority_type
     > pki:0010_auto__del_field_certificate_pem_encoded__del_field_certificateauthorit
     > pki:0011_add_pki_download_permission
     > pki:0012_auto__add_unique_keyusage_name__add_unique_extendedkeyusage_name
     - Loading initial data for pki.
    No fixtures found.

Nice. Your database has been migrated.

Update project's urls.py
========================

It is no longer required to specify the django-pki urls before the admin urls but the django-pki entry has changed. Your urls.py must look like this::
    
    (r'^admin/', include(admin.site.urls)),
    (r'^', include('pki.urls', 'pki')),

.. centered:: The update procedure is complete!
