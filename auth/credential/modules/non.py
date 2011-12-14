"""
None Credential
===============

:py:meth:`Non` - abstraction of a *none* credential

Description
-----------

This helper module for Credential implements a *none* credential,
that is the absence of authentication credential.

It does not support any attributes.

Copyright (C) 2011 CERN
"""

from auth.credential import Credential

class Non(Credential):
    _keys = {'scheme' : {'match' : 'none'}}
    
    def check(self):
        """ Check the none credential object """
        if self.__dict__ is None:
            return True
    