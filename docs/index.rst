.. _index:

==========================
django-pki - Web-based PKI
==========================

django-pki is a PKI based on Django ;-)

Introduction
=============

This project aims to simplify the installation and management of your personal CA infrastructure. Features include:

* Create CA chains based on self-signed Root CA's
* CA's can contain other CA's or non-CA certificates
* Automatic CRL generation/update when CA or related certificate is modified
* Creation and export of PEM, PKCS12 and DER encoded versions
* Revoke and renew of certificates

Online Resources
================

Sourcecode repository:
    https://github.com/dkerwin/django-pki/

Documentation:
    http://dkerwin.github.com/django-pki/

Issue tracker:
    https://github.com/dkerwin/django-pki/issues

Discussion:
    http://groups.google.com/group/django-pki

Getting started
===============

.. toctree::
   :maxdepth: 2
   :numbered:

   installation/install.rst
   installation/configuration.rst
   installation/upgrade.rst

Tutorial
========

*Coming soon...*

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

