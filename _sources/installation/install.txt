.. index:: Installation

============
Installation
============

Prequisites
===========

* Python (tested on 2.5 and 2.6)
* Django framework (>= 1.2)
* A RDBMS of your choice (MySQL, PostgreSQL, SQLite, Oracle)
* `OpenSSL <http://openssl.org/>`_
* Optional `jQuery library <http://jquery.com/>`_ (djago-pki already shipped with built-in jquery-1.5)
* `Graphviz <http://www.graphviz.org/>`_ + `pygraphviz <http://networkx.lanl.gov/pygraphviz/>`_ (Tree viewer and object locator requirement)
* zipfile Python library (Shipped with python)
* `south library <http://south.aeracode.org/>`_

pip / easy_install
==================

You can install django-pki via `pip <http://pypi.python.org/pypi/pip>`_ or easy_install::

    $ pip install django-pki
    
**or**
::

    $ easy_install django-pki

Sourcecode from GitHub
======================

Clone github repository (every release version is tagged)::

    $ git clone git://github.com/dkerwin/django-pki.git