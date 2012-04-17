"""
None Credential
===============

:py:meth:`Non` - abstraction of a *none* credential

Description
-----------

This helper module for Credential implements a *none* credential,
that is the absence of authentication credential.

It does not support any attributes.

Copyright (C) 2012 CERN
"""

from auth.credential import Credential

class Non(Credential):
    _keys = {'scheme' : {'match' : 'none'}}
    
    