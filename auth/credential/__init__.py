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
http://search.cpan.org/~lcons/Authen-Credential/

Copyright (C) 2011 CERN
"""
__version__ = "$Revision: 1 $"
# $Source$

from auth.credential.credential import new, parse, Credential