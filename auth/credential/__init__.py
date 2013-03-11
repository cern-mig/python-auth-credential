"""
This module offers an abstraction of a credential, i.e. something that
can be used to authenticate. It allows the creation and manipulation of
credentials. In particular, it defines a standard string representation
(so that credentials can be given to external programs as command line
options), a standard structured representation (so that credentials can
be stored in structured configuration files or using JSON) and
"preparators" that can transform credentials into ready-to-use data for
well known targets.

You can download the module at the following link:
http://pypi.python.org/pypi/auth.credential/

An Perl implementation of the same credential abstraction is available
in CPAN:
http://search.cpan.org/dist/Authen-Credential/

Copyright (C) 2013 CERN
"""
AUTHOR = "Massimo Paladin <massimo.paladin@gmail.com>"
COPYRIGHT = "Copyright (C) 2013 CERN"
VERSION = "1.0"
DATE = "4 Mar 2013"
__author__ = AUTHOR
__version__ = VERSION
__date__ = DATE

from auth.credential.credential import new, parse, Credential
