======================
python-auth-credential
======================

.. image:: https://github.com/cern-mig/python-auth-credential/actions/workflows/test.yml/badge.svg


Overview
========

This module offers an abstraction of a credential, i.e. something that
can be used to authenticate. It allows the creation and manipulation of
credentials. In particular, it defines a standard string representation
(so that credentials can be given to external programs as command line
options), a standard structured representation (so that credentials can
be stored in structured configuration files or using JSON) and
"preparators" that can transform credentials into ready-to-use data for
well known targets.

An Perl implementation of the same credential abstraction is available
in CPAN:

    http://search.cpan.org/dist/Authen-Credential/

Install
=======

To install this module, run the following command::

    python setup.py install

To test this module, run the following command::

    python setup.py test

Support and documentation
=========================

After installing, you can find documentation for this module with the
standard python help function command or at the following url:

    https://authcredential.readthedocs.org/

License and Copyright
=====================

Copyright (C) CERN 2013-2021

Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at 

    http://www.apache.org/licenses/LICENSE-2.0 

Unless required by applicable law or agreed to in writing, software 
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. 
See the License for the specific language governing permissions and 
limitations under the License.
