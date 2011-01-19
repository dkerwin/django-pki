.. index:: Installation

============
Installation
============

Prequisites
===========

* Python (tested on 2.5 and 2.6)
* Django framework (>=1.2 is recommended)
* A RDBMS of your choice (MySQL, PostgreSQL, SQLite, Oracle)
* Openssl
* Optional Jquery library (djago-pki already shipped with built-in jquery-1.3.2)
* pygraphviz + Graphviz (Tree viewer and object locator will not work without)
* zipfile Python library
* south library

pip / eays_install
==================

You can install django-pki via `pip <http://pypi.python.org/pypi/pip>`_ or easy_install::

    pip install django-pki
    
**or**::

    easy_install django-pki

Sourcecode from GitHub
======================

Clone github repository (every release version is tagged)::

    git clone git://github.com/dkerwin/django-pki.git