"""
:py:meth:`Credential` - abstraction of a credential

Synopsis
========

Example::

  import auth.credential as credential
  from auth.credential.modules.plain import Plain
  
  try:
      from urllib.request import Request
  except ImportError:
      from urllib2 import Request

  # creation
  option = {'scheme' : 'plain', 'name' : 'system', 'pass' : 'manager'}
  cred = credential.new(**option)
  assert option['scheme'] == cred['scheme']
  assert option['pass'] == cred['pass']
  # idem directly using the sub-class
  del(option['scheme'])
  cred = Plain(**option)

  # access the credential attributes
  if (cred.scheme == "plain"):
      print("user name is %s", cred.name)
      
  ### HTTP examples

  # use the prepare() method to get ready-to-use data
  headers = {"Authorization" : cred.prepare('HTTP.Basic')}
  req = Request("http://localhost", headers=headers)
  
  ### stomppy examples
  
  import stomp
  
  # plain example
  host_and_ports = [ ('localhost', 61613) ]
  params = cred.prepare('stomppy.plain')
  conn = stomp.Connection(host_and_ports, **params)
  
  # x509 example
  host_and_ports = [ ('localhost', 61612) ]
  option = {'scheme' : 'x509', 'key' : 'path/to/key', 'cert' : 'path/to/cert'}
  cred = credential.new(**option)
  params = cred.prepare('stomppy.x509')
  conn = stomp.Connection(host_and_ports, **params)
  

Description
===========

This module offers an abstraction of a credential, i.e. something that
can be used to authenticate. It allows the creation and manipulation
of credentials. In particular, it defines a standard string
representation (so that credentials can be given to external programs
as command line options), a standard structured representation (so
that credentials can be stored in structured configuration files or
using JSON) and "preparators" that can transform credentials into
ready-to-use data for well known targets.

Different authentication schemes (aka credential types) are supported.
This package currently supports *none*, *plain* and *x509* but
others can be added by providing the supporting code in a separate module.

For a given scheme, a credential is represented by an object with a
fixed set of string attributes. For instance, the *plain* scheme has
two attributes: *name* and *pass*. More information is provided by
the scheme specific module, for instance Plain.

String representation
=====================

The string representation of a credential is made of its scheme
followed by its attributes as key=value pairs, seperated by space.

For instance, for the *none* scheme with no attributes::

  none

And the the *plain* scheme with a name and password::

  plain name=system pass=manager

If needed, the characters can be URI-quoted, see urllib. All
non-alphanumerical characters should be escaped to avoid parsing
ambiguities.

The string representation is useful to give a program through its
command line options. For instance::

  myprog --uri http://foo:80 --auth "plain name=system pass=manager"


Structured representation
=========================

The structured representation of a credential is made of its scheme
and all its attributes as a string table.

Here is for instance how it could end up using JSON::

  {"scheme":"plain","name":"system","pass":"manager"}

The same information could be stored in a configuration file.

Copyright (C) 2011 CERN
"""
__version__ = "$Revision: 1 $"
# $Source$

from auth.credential.error import InvalidCredential
import re
import sys
try:
    from urllib.parse import quote, unquote
except ImportError:
    from urllib import quote, unquote

_ID_RE = '[a-z][a-z0-9]*'
ID_RE = re.compile(_ID_RE)
_SEP_CHARS = '[, ]'
SEP_CHARS = re.compile(_SEP_CHARS)
_VAL_CHARS = 'a-zA-Z0-9/\-\+\_\~\.\:'
_ID_VAL = "^(%s)=([%s\%%]*)$" % (_ID_RE, _VAL_CHARS)
ID_VAL = re.compile(_ID_VAL)

def parse(string):
    """
    Parse a string containing authentication information
    and return a dictionary.
    """
    string = string.strip()
    if not string:
        return new(scheme = 'none')
    auth = dict()
    tokens = SEP_CHARS.split(string)
    if len(tokens) == 0:
        raise InvalidCredential("invalid authentication string: %s" % string )
    if ID_RE.match(tokens[0]):
        auth['scheme'] = tokens[0]
        tokens.remove(tokens[0])
    format = re.compile(ID_VAL)
    for token in tokens:
        key_value = format.match(token)
        if not key_value:
            raise InvalidCredential("invalid authentication key=value: %s"
                            % token)
        if key_value.group(1) in auth:
            raise InvalidCredential("duplicate authentication key: %s"
                            % key_value.group(1))
        else:
            auth[key_value.group(1)] = unquote(key_value.group(2))
    return new(**auth)

def new(**option):
    """
    Return a Credential object according to the option passed and
    the given scheme.
    """
    atype = option.get("scheme", "non")
    if atype == "none":
        atype = "non"
    try:
        __import__("auth.credential.modules.%s" % (atype))
    except SyntaxError:
        raise SyntaxError("error importing credential type: %s" % atype)
    except ImportError:
        raise InvalidCredential("credential type not supported: %s" % atype)
    try:
        module = sys.modules["auth.credential.modules.%s" % (atype)]
        return getattr(module, atype.capitalize())(**option)
    except KeyError:
        pass
    raise InvalidCredential("credential type not valid: %s" % atype)

class Credential(object):
    _keys = []
    _preparator = None
    
    def __init__(self, **option):
        """ Credential constructor """
        if option is None:
            option = dict()
        if 'scheme' in self._keys and 'scheme' not in option:
            option['scheme'] = self._keys['scheme']['match']
            print("<%s>" % option['scheme'])
        for key, value in self._keys.items():
            optional = value.get("optional", False)
            if (not optional) and key not in option:
                raise InvalidCredential("attribute missing: %s" % key)
            match = value.get('match', None)
            if match is not None and option[key] != match:
                raise InvalidCredential("invalid value for: %s" % key)
        for key, value in option.items():
            if key not in self._keys:
                raise InvalidCredential("attribute not expected: %s" % key)
            self.__dict__[key] = value
            
    def __getitem__(self, name):
        """ Return item from attributes. """
        return self.__dict__[name]
    
    def dict(self):
        """ Return a dict representation of the credential. """
        return self.__dict__
    
    def __repr__(self):
        """ Return string representation of the object. """
        return self.string()
    
    def string(self):
        """ Convert the given authentication information into a string. """
        try:
            if not self.scheme:
                raise InvalidCredential("invalid credential: no scheme")
        except AttributeError:
            raise InvalidCredential("invalid credential: no scheme")
        partial = [self.scheme]
        for key, value in self.__dict__.items():
            if key == 'scheme':
                continue
            partial.append("%s=%s" % (key, quote(value, _VAL_CHARS)))
        return ' '.join(partial)
    
    def check(self):
        """ Check if the given authentication is valid.
        Return True if not implemented. """
        return True
    
    def __eq__(self, other):
        """ Check if the credential is equal to the given one. """
        if not isinstance(other, Credential):
            return False
        return self.__dict__ == other.__dict__
    
    def equals(self, other):
        """ Check if the credential is equal to the given one. """
        return self.__eq__(other)
    
    def prepare(self, target):
        """ Generic preparator. """
        if target not in self._preparator:
            raise InvalidCredential("target not supported")
        return getattr(self, self._preparator[target])()
