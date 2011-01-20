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

Getting started
===============

.. toctree::
   :maxdepth: 2
   :numbered:

   installation/install.rst
   installation/configuration.rst

Tutorial
========

.. toctree::
   :maxdepth: 2
   :numbered:
   
   tutorial/ca.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

