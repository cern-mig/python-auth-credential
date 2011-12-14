"""
Plain Credential
================

:py:meth:`Plain` - abstraction of a *plain* credential

Description
-----------

This helper module for Credential implements a *plain* credential,
that is a pair of name and clear text password.

It supports the following attributes:

name
    the (usually user) name

pass
    the associated (clear text) password

Copyright (C) 2011 CERN
"""

from auth.credential import Credential
import base64

class Plain(Credential):
    _keys = {'scheme' : {'match' : 'plain'},
             'name': dict(),
             'pass': dict(),}
    _preparator = dict()
    
    def check(self):
        """ Check the none credential object """
        if self.__dict__ is None:
            return True
        
    def _prepare_http_basic(self):
        """ Return the Authorization header for an HTTP Request """
        tmp = "%s:%s" % (self.__dict__['name'], self.__dict__['pass'])
        return "Basic %s" % base64.b64encode(tmp.encode()).decode()
    _preparator["HTTP.Basic"] = "_prepare_http_basic"
    
    def _prepare_stomppy_plain(self):
        """ Return parameter to be passed to stomppy creating connection """
        params = dict()
        if self.__dict__.get('name'):
            params['user'] = self.__dict__.get('name')
        if self.__dict__.get('pass'):
            params['passcode'] = self.__dict__.get('pass')
        return params
    _preparator["stomppy.plain"] = "_prepare_stomppy_plain"
