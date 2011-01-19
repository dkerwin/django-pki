.. _index:

django-pki - PKI based on Django
================================

This project aims to simplify the installation and management of your personal CA infrastructure. Features include:

* Create CA chains based on self-signed Root CA's
* CA's can contain other CA's or non-CA certificates
* Automatic CRL generation/update when CA or related certificate is modified
* Creation and export of PEM, PKCS12 and DER encoded versions
* Revoke and renew of certificates
    
Installation / Configuration
============================

.. toctree::
   :numbered:
   :maxdepth: 2

   installation/install.rst
   installation/configuration.rst


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

