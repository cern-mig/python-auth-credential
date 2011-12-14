"""
X509 Credential
===============

:py:meth:`X509` - abstraction of an X.509 credential

Description
-----------

This helper module for Credential implements an X.509
credential, see http://en.wikipedia.org/wiki/X.509.

It supports the following attributes:

cert
    the path of the file holding the certificate

key
    the path of the file holding the private key

pass
    the pass-phrase protecting the private key (optional)

ca
    the path of the directory containing trusted certificates (optional)
    
Copyright (C) 2011 CERN
"""

from auth.credential import Credential

class X509(Credential):
    _keys = {'scheme' : {'match' : 'x509'},
             'cert' : {'optional' : True},
             'key': {'optional' : True},
             'pass': {'optional' : True},
             'ca': {'optional' : True}}
    _preparator = dict()
    
    def check(self):
        """ Check the none credential object """
        if self.__dict__ is None:
            return True
        
    def _prepare_stomppy(self):
        """ Return parameter to be passed to stomppy creating connection """
        params = {'use_ssl' : True}
        if self.__dict__.get('key'):
            params['ssl_key_file'] = self.__dict__.get('key')
        if self.__dict__.get('cert'):
            params['ssl_cert_file'] = self.__dict__.get('cert')
        if self.__dict__.get('ca'):
            params['ssl_ca_certs'] = self.__dict__.get('ca')
        return params
    _preparator["stomppy.x509"] = "_prepare_stomppy"
